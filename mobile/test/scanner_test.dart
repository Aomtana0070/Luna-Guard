import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:luna_guard_mobile/scanner.dart';

void main() {
  test('streams the file and produces a stable SHA-256', () async {
    final result = await FileScanner.scan(
      name: 'sample.exe',
      content: Stream<List<int>>.fromIterable([
        ascii.encode('MZ'),
        ascii.encode('ordinary executable bytes'),
      ]),
    );

    expect(result.sha256,
        '1f01209e748ebd539133ceaf1f62a4657b261c3f9b9ba20fdccddc245eb9d7bc');
    expect(result.complete, isTrue);
    expect(result.level, FindingLevel.clean);
  });

  test('detects XWorm-specific strings split across input chunks', () async {
    final content = Stream<List<int>>.fromIterable([
      [0x4d, 0x5a, ...ascii.encode('mscoree.dll BSJB <Xworm')],
      ascii.encode('mm> Xklog'),
    ]);
    final result = await FileScanner.scan(name: 'sample.exe', content: content);

    expect(result.level, FindingLevel.high);
    expect(result.reasons.single, 'reason.xwormHigh');
  });

  test('a single XWorm-specific marker needs manual review, not HIGH', () async {
    final result = await FileScanner.scan(
      name: 'vivoxsdk.dll',
      content: Stream<List<int>>.value(
        ascii.encode('MZ mscoree.dll BSJB <Xwormmm>'),
      ),
    );

    expect(result.level, FindingLevel.medium);
    expect(result.reasons, contains('reason.xwormReview'));
  });

  test('a generic XWorm string is not classified as HIGH', () async {
    final result = await FileScanner.scan(
      name: 'vivoxsdk.dll',
      content: Stream<List<int>>.value(
        ascii.encode('MZ mscoree.dll BSJB xworm'),
      ),
    );

    expect(result.level, FindingLevel.medium);
    expect(result.reasons, contains('reason.xwormReview'));
  });

  test('marks archives incomplete instead of reporting them clean', () async {
    final result = await FileScanner.scan(
      name: 'document.docx',
      content: Stream<List<int>>.value(ascii.encode('ordinary bytes')),
    );

    expect(result.level, FindingLevel.clean);
    expect(result.complete, isFalse);
    expect(result.reasons, contains('reason.archiveUnsupported'));
  });

  test('matches hashes imported on this device', () async {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    final result = await FileScanner.scan(
      name: 'empty.exe',
      content: const Stream<List<int>>.empty(),
      knownHashes: {hash},
    );

    expect(result.sha256, hash);
    expect(result.level, FindingLevel.high);
  });

  test('detects a PowerShell downloader without loading the full file', () async {
    final result = await FileScanner.scan(
      name: 'loader.ps1',
      content: Stream<List<int>>.fromIterable([
        ascii.encode('DownloadString; FromBase64String; '),
        ascii.encode('-WindowStyle Hidden'),
      ]),
    );

    expect(result.level, FindingLevel.medium);
    expect(result.complete, isTrue);
  });

  test('parses only complete SHA-256 values from an imported list', () {
    expect(
      parseSha256List(
        'bad\n'
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, malware\n'
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550\n',
      ),
      {'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
    );
  });
}
