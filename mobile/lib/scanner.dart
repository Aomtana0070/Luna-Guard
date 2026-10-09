import 'dart:convert';

import 'package:crypto/crypto.dart';

enum FindingLevel { high, medium, low, clean }

class FileScanResult {
  const FileScanResult({
    required this.name,
    required this.sha256,
    required this.bytes,
    required this.scannedAt,
    required this.level,
    required this.reasons,
    required this.complete,
  });

  final String name;
  final String sha256;
  final int bytes;
  final DateTime scannedAt;
  final FindingLevel level;
  final List<String> reasons;
  final bool complete;

  Map<String, Object> toJson() => {
        'name': name,
        'sha256': sha256,
        'bytes': bytes,
        'scannedAt': scannedAt.toIso8601String(),
        'level': level.name,
        'reasons': reasons,
        'complete': complete,
      };

  factory FileScanResult.fromJson(Map<String, dynamic> json) => FileScanResult(
        name: json['name'] as String,
        sha256: json['sha256'] as String,
        bytes: json['bytes'] as int,
        scannedAt: DateTime.parse(json['scannedAt'] as String),
        level: FindingLevel.values.byName(json['level'] as String),
        reasons: List<String>.from(json['reasons'] as List),
        complete: json['complete'] as bool,
      );
}

class FileScanner {
  static const _scriptExtensions = {
    '.exe',
    '.dll',
    '.scr',
    '.com',
    '.bat',
    '.cmd',
    '.ps1',
    '.vbs',
    '.js',
  };
  static const _archiveExtensions = {
    '.zip',
    '.jar',
    '.docx',
    '.docm',
    '.xlsx',
    '.xlsm',
    '.pptx',
    '.pptm',
    '.apk',
  };
  static const _wormSignatures = ['<xwormmm>', 'xworm v', 'xklog'];
  static const _powerShellDownload = 'downloadstring';
  static const _powerShellBase64 = 'frombase64string';
  static const _powerShellHidden = '-windowstyle hidden';
  static const _powerShellBypass = '-executionpolicy bypass';
  static const _defenderExclusion = 'add-mppreference';

  static Future<FileScanResult> scan({
    required String name,
    required Stream<List<int>> content,
    Set<String> knownHashes = const {},
  }) async {
    final digestSink = AccumulatorSink<Digest>();
    final hashInput = sha256.startChunkedConversion(digestSink);
    final extension = _extension(name);
    final isScript = _scriptExtensions.contains(extension);
    final isArchive = _archiveExtensions.contains(extension);
    final isExecutable = extension == '.exe' || extension == '.dll' ||
        extension == '.scr' || extension == '.com';
    final carryLimit = 192;
    var carry = <int>[];
    var prefix = <int>[];
    var totalBytes = 0;
    var hasMscoreeMarker = false;
    var hasBsjbMarker = false;
    var hasXworm = false;
    var hasWeakXworm = false;
    var hasDownload = false;
    var hasBase64 = false;
    var hasHidden = false;
    var hasBypass = false;
    var hasDefenderExclusion = false;

    await for (final chunk in content) {
      hashInput.add(chunk);
      totalBytes += chunk.length;
      if (prefix.length < 2) {
        prefix.addAll(chunk.take(2 - prefix.length));
      }
      final combined = <int>[...carry, ...chunk];
      final lower = _asciiLower(combined);
      final text = latin1.decode(lower);
      bool containsAscii(String value) => text.contains(value);
      bool containsWide(String value) =>
          text.contains(latin1.decode(_toWideAscii(ascii.encode(value))));
      hasMscoreeMarker |= containsAscii('mscoree.dll');
      hasBsjbMarker |= containsAscii('bsjb');
      hasXworm |= _wormSignatures
          .any((marker) => containsAscii(marker) || containsWide(marker));
      hasWeakXworm |= containsAscii('xworm') || containsWide('xworm');
      hasDownload |= containsAscii(_powerShellDownload) ||
          containsWide(_powerShellDownload);
      hasBase64 |=
          containsAscii(_powerShellBase64) || containsWide(_powerShellBase64);
      hasHidden |=
          containsAscii(_powerShellHidden) || containsWide(_powerShellHidden);
      hasBypass |=
          containsAscii(_powerShellBypass) || containsWide(_powerShellBypass);
      hasDefenderExclusion |= containsAscii(_defenderExclusion) ||
          containsWide(_defenderExclusion);
      carry = combined.length <= carryLimit
          ? combined
          : combined.sublist(combined.length - carryLimit);
    }
    hashInput.close();
    final hash = digestSink.events.single.toString();
    final reasons = <String>[];
    var level = FindingLevel.clean;
    var complete = true;
    final hasDotnetMarker = hasMscoreeMarker && hasBsjbMarker;

    if (knownHashes.contains(hash)) {
      level = FindingLevel.high;
      reasons.add('reason.hashMatch');
    }

    if (isScript &&
        prefix.length == 2 &&
        prefix[0] == 0x4d &&
        prefix[1] == 0x5a) {
      if (hasDotnetMarker && hasXworm) {
        level = FindingLevel.high;
        reasons.add('reason.xwormHigh');
      } else if (totalBytes < 5 * 1024 * 1024 &&
          hasDotnetMarker &&
          hasWeakXworm &&
          level != FindingLevel.high) {
        level = FindingLevel.medium;
        reasons.add('reason.xwormReview');
      }
    } else if (isScript &&
        totalBytes < 1024 * 1024 &&
        hasDownload &&
        hasBase64 &&
        (hasHidden || hasBypass)) {
      if (level != FindingLevel.high) level = FindingLevel.medium;
      reasons.add('reason.scriptLoader');
    } else if (isScript &&
        totalBytes < 1024 * 1024 &&
        hasDefenderExclusion &&
        (hasDownload || hasBase64)) {
      if (level != FindingLevel.high) level = FindingLevel.medium;
      reasons.add('reason.defenderLoader');
    } else if (isScript &&
        totalBytes < 1024 * 1024 &&
        hasHidden &&
        hasBypass &&
        level == FindingLevel.clean) {
      level = FindingLevel.low;
      reasons.add('reason.hiddenPolicy');
    }

    if (isArchive) {
      complete = false;
      reasons.add('reason.archiveUnsupported');
    } else if (!isScript && !isExecutable) {
      complete = false;
      reasons.add('reason.typeUnsupported');
    }
    if (reasons.isEmpty) {
      reasons.add('reason.noMatch');
    }

    return FileScanResult(
      name: name,
      sha256: hash,
      bytes: totalBytes,
      scannedAt: DateTime.now(),
      level: level,
      reasons: reasons,
      complete: complete,
    );
  }

  static String _extension(String name) {
    final dot = name.lastIndexOf('.');
    return dot < 0 ? '' : name.substring(dot).toLowerCase();
  }

  static List<int> _asciiLower(List<int> bytes) => bytes
      .map((byte) => byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte)
      .toList(growable: false);

  static List<int> _toWideAscii(List<int> bytes) =>
      bytes.expand((byte) => [byte, 0]).toList(growable: false);

}

Set<String> parseSha256List(String contents) {
  final hashes = <String>{};
  final expression = RegExp(r'[0-9a-fA-F]{64}');
  for (final match in expression.allMatches(contents)) {
    final before = match.start > 0 ? contents[match.start - 1] : '';
    final after =
        match.end < contents.length ? contents[match.end] : '';
    if (RegExp(r'[0-9a-fA-F]').hasMatch(before) ||
        RegExp(r'[0-9a-fA-F]').hasMatch(after)) {
      continue;
    }
    hashes.add(match.group(0)!.toLowerCase());
  }
  return hashes;
}
