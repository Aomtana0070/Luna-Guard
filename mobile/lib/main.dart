import 'dart:convert';
import 'dart:io' show Platform;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:saf/saf.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'scanner.dart';

void main() => runApp(const LunaGuardMobileApp());

const _translations = <String, Map<String, String>>{
  'th': {
    'scan': 'สแกนไฟล์',
    'history': 'ประวัติ',
    'guide': 'คู่มือ',
    'settings': 'ตั้งค่า',
    'tagline': 'ตรวจไฟล์บนอุปกรณ์ของคุณ',
    'scanTitle': 'เลือกไฟล์ที่ต้องการตรวจ',
    'scanInfo':
        'เลือกไฟล์ได้หลายไฟล์เพื่อตรวจด้วย SHA-256 และกฎออฟไลน์ ข้อมูลจะประมวลผลในเครื่องและไม่ถูกอัปโหลด',
    'scanInfoAndroid':
        'เลือกหลายไฟล์ หรือเลือกโฟลเดอร์ที่ Android อนุญาตเพื่อสแกนไฟล์และโฟลเดอร์ย่อยซ้ำ ข้อมูลจะประมวลผลในเครื่องและไม่ถูกอัปโหลด',
    'pickFiles': 'เลือกไฟล์เพื่อสแกน',
    'scanning': 'กำลังตรวจไฟล์…',
    'scanProgress': 'กำลังตรวจไฟล์ที่ {current} จาก {total}',
    'scanProgressBytes': 'ไฟล์ {current}/{total} · {bytes} ไบต์',
    'scanFolder': 'เลือกโฟลเดอร์เพื่อสแกน',
    'scanSavedFolder': 'สแกนโฟลเดอร์ {folder}',
    'changeFolder': 'เปลี่ยนโฟลเดอร์',
    'folderProgress': 'ตรวจแล้ว {count} ไฟล์ · {name} · {bytes} ไบต์',
    'folderScanDone': 'ตรวจแล้ว {count} ไฟล์ · พบ {findings} รายการ · อ่านไม่สำเร็จ {errors}',
    'folderScanError': 'สแกนโฟลเดอร์ไม่สำเร็จ: {error}',
    'folderPermissionExpired': 'สิทธิ์เข้าถึงโฟลเดอร์หมดอายุ กรุณาเลือกโฟลเดอร์ใหม่',
    'stopScan': 'หยุดสแกน',
    'scanStopped': 'หยุดสแกนแล้วหลังตรวจ {count} ไฟล์',
    'privacyTitle': 'ขอบเขตการทำงานบนมือถือ',
    'privacyInfo':
        'Android: เลือกโฟลเดอร์ที่อนุญาตเพื่อสแกนไฟล์และโฟลเดอร์ย่อยซ้ำได้; iOS: เลือกไฟล์เอง แอปไม่สแกนหน่วยความจำหรือพื้นที่ส่วนตัวของแอปอื่น และไฟล์บีบอัดจะระบุว่าสแกนไม่ครบ',
    'noThreats': 'ไม่พบรูปแบบที่รู้จัก',
    'threatFound': 'พบสิ่งน่าสงสัย',
    'scanIncomplete': 'สแกนไม่ครบ',
    'hash': 'SHA-256',
    'fileSize': 'ขนาด',
    'filePath': 'ชื่อไฟล์ / ตำแหน่ง',
    'bytes': 'ไบต์',
    'why': 'รายละเอียด',
    'noHistory': 'ยังไม่มีประวัติการสแกน',
    'guideText':
        'เลือกไฟล์จากตัวเลือกไฟล์ของ Android หรือ iOS แอปอ่านไฟล์ทีละส่วนและคำนวณ SHA-256 บนอุปกรณ์ การสแกนเป็นแบบอ่านอย่างเดียว',
    'guideLimits':
        'บน Android เลือกโฟลเดอร์ที่ระบบอนุญาตเพื่อสแกนไฟล์ในโฟลเดอร์และโฟลเดอร์ย่อยได้ แอปไม่สามารถเข้าถึงข้อมูลส่วนตัวของแอปอื่นหรือบางโฟลเดอร์ระบบได้ บน iOS ต้องเลือกไฟล์เอง กฎมือถือเป็นชุดตรวจจับพื้นฐาน ไม่ใช่เอนจิน YARA เต็มรูปแบบ และไม่รับประกันว่าจะพบมัลแวร์ทุกชนิด',
    'hashTitle': 'รายการ SHA-256 ในเครื่อง',
    'hashInfo':
        'นำเข้าไฟล์ข้อความที่มี SHA-256 ที่เชื่อถือได้ รายการจะเก็บในอุปกรณ์นี้เท่านั้น',
    'importHashes': 'นำเข้ารายการ SHA-256',
    'hashImportSuccess': 'นำเข้า {count} แฮชแล้ว',
    'hashImportEmpty': 'ไม่พบ SHA-256 ที่ถูกต้องในไฟล์',
    'hashLimit': 'นำเข้าเกินขีดจำกัด 5,000 แฮช',
    'language': 'ภาษา',
    'languageSaved': 'เปลี่ยนภาษาแล้ว',
    'scanError': 'สแกนไฟล์ไม่สำเร็จ: {error}',
    'importError': 'นำเข้ารายการไม่สำเร็จ: {error}',
    'high': 'สูง',
    'medium': 'ปานกลาง',
    'low': 'ต่ำ',
    'clean': 'ไม่พบรูปแบบ',
    'threatNotice':
        'ผลไม่พบรูปแบบไม่ได้ยืนยันว่าไฟล์หรืออุปกรณ์ปลอดภัยทั้งหมด',
    'reason.hashMatch': 'SHA-256 ตรงกับรายการแฮชที่นำเข้าไว้ในอุปกรณ์',
    'reason.xwormHigh': 'พบสตริงเฉพาะของ XWorm และตัวบ่งชี้ .NET',
    'reason.xwormReview':
        'พบสัญญาณ XWorm หรือคำทั่วไปเพียงบางส่วนร่วมกับตัวบ่งชี้ .NET ควรตรวจสอบเพิ่มเติม ไม่ใช่การยืนยันว่าติดเชื้อ',
    'reason.scriptLoader':
        'สคริปต์มีการดาวน์โหลด ถอดรหัส Base64 และสัญญาณการซ่อนตัว',
    'reason.defenderLoader':
        'สคริปต์มีคำสั่งยกเว้น Defender ร่วมกับสัญญาณของ loader',
    'reason.hiddenPolicy':
        'สคริปต์ซ่อนหน้าต่างและข้าม execution policy ควรตรวจสอบ',
    'reason.archiveUnsupported': 'แอปมือถือยังไม่ได้ตรวจเนื้อหาภายใน archive',
    'reason.typeUnsupported': 'ยังไม่มีกฎตรวจเนื้อหาสำหรับไฟล์ชนิดนี้',
    'reason.noMatch':
        'ไม่พบรูปแบบที่รู้จัก ซึ่งไม่ได้รับประกันว่าไฟล์ปลอดภัย',
  },
  'en': {
    'scan': 'Scan',
    'history': 'History',
    'guide': 'Guide',
    'settings': 'Settings',
    'tagline': 'On-device file checks',
    'scanTitle': 'Choose files to inspect',
    'scanInfo':
        'Select multiple files for sequential SHA-256 and offline signature checks. Files are processed on-device and never uploaded.',
    'scanInfoAndroid':
        'Select multiple files or an Android-authorized folder to rescan its files and subfolders. Data is processed on-device and never uploaded.',
    'pickFiles': 'Choose files',
    'scanning': 'Inspecting files…',
    'scanProgress': 'Inspecting file {current} of {total}',
    'scanProgressBytes': 'File {current}/{total} · {bytes} bytes',
    'scanFolder': 'Choose folder to scan',
    'scanSavedFolder': 'Scan saved folder: {folder}',
    'changeFolder': 'Change folder',
    'folderProgress': 'Scanned {count} files · {name} · {bytes} bytes',
    'folderScanDone': 'Scanned {count} files · {findings} findings · {errors} read errors',
    'folderScanError': 'Could not scan folder: {error}',
    'folderPermissionExpired': 'Folder access expired. Choose the folder again.',
    'stopScan': 'Stop scan',
    'scanStopped': 'Scan stopped after {count} files',
    'privacyTitle': 'Mobile scanning scope',
    'privacyInfo':
        'Android: choose an allowed folder to rescan its files and subfolders. iOS: select files manually. The app cannot scan memory or other apps’ private storage; archives are marked incomplete.',
    'noThreats': 'No known pattern found',
    'threatFound': 'Suspicious pattern found',
    'scanIncomplete': 'Scan incomplete',
    'hash': 'SHA-256',
    'fileSize': 'Size',
    'filePath': 'File / path',
    'bytes': 'bytes',
    'why': 'Details',
    'noHistory': 'No scan history yet',
    'guideText':
        'Choose files using the Android or iOS file picker. Luna Guard reads selected files in chunks and computes SHA-256 on-device. Scanning is read-only.',
    'guideLimits':
        'On Android, choose a system-authorized folder to scan its files and subfolders. The app cannot access other apps’ private data or some protected system folders. On iOS, select files individually. Mobile detection uses a basic signature set, not the full YARA engine, and cannot guarantee detection of every threat.',
    'hashTitle': 'Local SHA-256 list',
    'hashInfo':
        'Import a text file containing trusted SHA-256 values. The list stays on this device.',
    'importHashes': 'Import SHA-256 list',
    'hashImportSuccess': 'Imported {count} hashes',
    'hashImportEmpty': 'No valid SHA-256 values found in that file',
    'hashLimit': 'The import exceeds the 5,000-hash limit',
    'language': 'Language',
    'languageSaved': 'Language changed',
    'scanError': 'Could not scan file: {error}',
    'importError': 'Could not import list: {error}',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'clean': 'No pattern found',
    'threatNotice':
        'A result with no known pattern does not prove a file or device is safe.',
    'reason.hashMatch': 'SHA-256 matches a hash list imported on this device.',
    'reason.xwormHigh':
        'At least two distinct XWorm-specific strings and .NET markers found.',
    'reason.xwormReview':
        'A partial or generic XWorm string and .NET markers were found; review manually. This does not confirm infection.',
    'reason.scriptLoader':
        'Script combines network download, Base64 decoding, and stealth indicators.',
    'reason.defenderLoader':
        'Script combines a Defender exclusion command with a loader indicator.',
    'reason.hiddenPolicy':
        'Script hides its window and bypasses execution policy; review manually.',
    'reason.archiveUnsupported':
        'Archive contents are not inspected by the mobile scanner.',
    'reason.typeUnsupported':
        'This file type has no content signatures in the mobile scanner.',
    'reason.noMatch':
        'No bundled signature matched; this is not a guarantee the file is safe.',
  },
  'zh-CN': {
    'scan': '扫描',
    'history': '历史',
    'guide': '指南',
    'settings': '设置',
    'tagline': '本机文件检查',
    'scanTitle': '选择要检查的文件',
    'scanInfo': '可选择多个文件，依次使用 SHA-256 和离线特征检查。文件仅在设备上处理，不会上传。',
    'scanInfoAndroid': '可选择多个文件，或选择 Android 授权的文件夹以重复扫描其中的文件和子文件夹。数据仅在设备上处理，不会上传。',
    'pickFiles': '选择文件',
    'scanning': '正在检查文件…',
    'scanProgress': '正在检查第 {current} 个文件，共 {total} 个',
    'scanProgressBytes': '文件 {current}/{total} · {bytes} 字节',
    'scanFolder': '选择要扫描的文件夹',
    'scanSavedFolder': '扫描已保存的文件夹：{folder}',
    'changeFolder': '更改文件夹',
    'folderProgress': '已扫描 {count} 个文件 · {name} · {bytes} 字节',
    'folderScanDone': '已扫描 {count} 个文件 · 发现 {findings} 项 · 读取错误 {errors} 项',
    'folderScanError': '无法扫描文件夹：{error}',
    'folderPermissionExpired': '文件夹访问权限已失效，请重新选择文件夹。',
    'stopScan': '停止扫描',
    'scanStopped': '已在扫描 {count} 个文件后停止',
    'privacyTitle': '手机扫描范围',
    'privacyInfo': 'Android：选择一个授权文件夹即可重复扫描其中的文件和子文件夹。iOS：请手动选择文件。应用无法扫描内存或其他应用的私有存储；压缩包会标记为扫描未完成。',
    'noThreats': '未发现已知特征',
    'threatFound': '发现可疑特征',
    'scanIncomplete': '扫描未完成',
    'hash': 'SHA-256',
    'fileSize': '大小',
    'filePath': '文件/路径',
    'bytes': '字节',
    'why': '详情',
    'noHistory': '暂无扫描历史',
    'guideText': '使用 Android 或 iOS 文件选择器选择文件。Luna Guard 会在本机分块读取并计算 SHA-256。扫描为只读。',
    'guideLimits': '在 Android 上，选择一个系统授权的文件夹即可扫描其中的文件和子文件夹。应用无法访问其他应用的私有数据或部分受保护的系统文件夹。在 iOS 上，请逐个选择文件。移动版使用基础特征，而非完整 YARA 引擎，不能保证检测所有威胁。',
    'hashTitle': '本机 SHA-256 列表',
    'hashInfo': '导入包含可信 SHA-256 值的文本文件。列表仅保存在此设备。',
    'importHashes': '导入 SHA-256 列表',
    'hashImportSuccess': '已导入 {count} 个哈希',
    'hashImportEmpty': '文件中没有有效的 SHA-256 值',
    'hashLimit': '导入内容超过 5,000 个哈希的上限',
    'language': '语言',
    'languageSaved': '语言已更改',
    'scanError': '无法扫描文件：{error}',
    'importError': '无法导入列表：{error}',
    'high': '高',
    'medium': '中',
    'low': '低',
    'clean': '未发现特征',
    'threatNotice': '未发现已知特征不代表文件或设备绝对安全。',
    'reason.hashMatch': 'SHA-256 与本机导入的哈希列表匹配。',
    'reason.xwormHigh': '发现至少两个不同的 XWorm 特征字符串和 .NET 标记。',
    'reason.xwormReview': '发现部分或通用 XWorm 字符串及 .NET 标记，请人工检查；这不能确认设备已感染。',
    'reason.scriptLoader': '脚本同时包含网络下载、Base64 解码和隐藏执行特征。',
    'reason.defenderLoader': '脚本同时包含 Defender 排除命令和加载器特征。',
    'reason.hiddenPolicy': '脚本隐藏窗口并绕过执行策略，请人工检查。',
    'reason.archiveUnsupported': '移动版尚未检查压缩包内部内容。',
    'reason.typeUnsupported': '移动版没有此文件类型的内容特征规则。',
    'reason.noMatch': '未匹配内置特征，但这不代表文件绝对安全。',
  },
};

class LunaGuardMobileApp extends StatefulWidget {
  const LunaGuardMobileApp({super.key});

  @override
  State<LunaGuardMobileApp> createState() => _LunaGuardMobileAppState();
}

class _LunaGuardMobileAppState extends State<LunaGuardMobileApp> {
  final _preferences = SharedPreferencesAsync();
  final _saf = Saf();
  String _language = 'th';
  Set<String> _knownHashes = {};
  List<FileScanResult> _history = [];
  List<FileScanResult> _lastResults = [];
  int _tab = 0;
  bool _ready = false;
  bool _scanning = false;
  int _scanProgress = 0;
  int _scanTotal = 0;
  int _scanBytes = 0;
  String _scanCurrentName = '';
  bool _cancelScan = false;
  String? _autoScanFolderUri;
  String? _autoScanFolderName;
  String? _loadError;

  String tr(String key, [Map<String, String> values = const {}]) {
    var value = _translations[_language]![key] ?? key;
    for (final entry in values.entries) {
      value = value.replaceAll('{${entry.key}}', entry.value);
    }
    return value;
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final language = await _preferences.getString('language') ?? 'th';
      final hashes = await _preferences.getStringList('known_hashes') ?? [];
      final autoScanFolderUri =
          await _preferences.getString('auto_scan_folder_uri');
      final autoScanFolderName =
          await _preferences.getString('auto_scan_folder_name');
      final rawHistory = await _preferences.getString('scan_history');
      final decoded = rawHistory == null
          ? <dynamic>[]
          : jsonDecode(rawHistory) as List<dynamic>;
      if (!mounted) return;
      setState(() {
        _language = _translations.containsKey(language) ? language : 'th';
        _knownHashes = hashes.toSet();
        _autoScanFolderUri = autoScanFolderUri;
        _autoScanFolderName = autoScanFolderName;
        _history = decoded
            .map((entry) => FileScanResult.fromJson(
                Map<String, dynamic>.from(entry as Map)))
            .toList();
        _ready = true;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _ready = true;
        _loadError = error.toString();
      });
    }
  }

  Future<void> _saveHistory() async {
    _history = _history.take(50).toList();
    await _preferences.setString(
      'scan_history',
      jsonEncode(_history.map((item) => item.toJson()).toList()),
    );
  }

  Future<void> _selectAndScan() async {
    try {
      final files = await FilePicker.pickFiles(type: FileType.any);
      if (files.isEmpty || !mounted) return;
      setState(() {
        _scanning = true;
        _cancelScan = false;
        _scanProgress = 0;
        _scanTotal = files.length;
        _scanBytes = 0;
        _lastResults = [];
      });
      final results = <FileScanResult>[];
      for (var index = 0; index < files.length; index++) {
        if (_cancelScan) break;
        final file = files[index];
        if (mounted) {
          setState(() {
            _scanProgress = index + 1;
            _scanCurrentName = file.name;
            _scanBytes = 0;
          });
        }
        try {
          final result = await FileScanner.scan(
            name: file.name,
            content: file.readAsByteStream(),
            knownHashes: _knownHashes,
            onProgress: (bytes) {
              if (mounted) setState(() => _scanBytes = bytes);
            },
            isCancelled: () => _cancelScan,
          );
          results.add(result);
        } on ScanCancelledException {
          break;
        } catch (error) {
          results.add(FileScanResult(
            name: file.name,
            sha256: '',
            bytes: 0,
            scannedAt: DateTime.now(),
            level: FindingLevel.clean,
            reasons: [tr('scanError', {'error': error.toString()})],
            complete: false,
          ));
        }
      }
      if (!mounted) return;
      setState(() {
        _lastResults = results;
        _history.insertAll(0, results);
        _scanning = false;
        _scanProgress = 0;
        _scanTotal = 0;
        _scanBytes = 0;
      });
      await _saveHistory();
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _scanning = false;
        _scanProgress = 0;
        _scanTotal = 0;
        _scanBytes = 0;
      });
      _message(tr('scanError', {'error': error.toString()}));
    }
  }

  Future<void> _pickAutoScanFolder() async {
    try {
      final folder = await _saf.pickDirectory(
        writePermission: false,
        persistablePermission: true,
      );
      if (folder == null || !mounted) return;
      await _preferences.setString('auto_scan_folder_uri', folder.uri);
      await _preferences.setString('auto_scan_folder_name', folder.name);
      if (!mounted) return;
      setState(() {
        _autoScanFolderUri = folder.uri;
        _autoScanFolderName = folder.name;
      });
      await _scanAutoFolder(folder.uri, folder.name);
    } catch (error) {
      if (!mounted) return;
      _message(tr('folderScanError', {'error': error.toString()}));
    }
  }

  Future<void> _scanSavedAutoFolder() async {
    final uri = _autoScanFolderUri;
    if (uri == null) {
      await _pickAutoScanFolder();
      return;
    }
    try {
      final permissions = await _saf.persistedPermissions();
      if (!permissions.any((permission) => permission.uri == uri)) {
        await _preferences.remove('auto_scan_folder_uri');
        await _preferences.remove('auto_scan_folder_name');
        if (!mounted) return;
        setState(() {
          _autoScanFolderUri = null;
          _autoScanFolderName = null;
        });
        _message(tr('folderPermissionExpired'));
        return;
      }
      await _scanAutoFolder(uri, _autoScanFolderName ?? uri);
    } catch (error) {
      if (!mounted) return;
      _message(tr('folderScanError', {'error': error.toString()}));
    }
  }

  Future<void> _scanAutoFolder(String uri, String folderName) async {
    if (_scanning) return;
    setState(() {
      _scanning = true;
      _cancelScan = false;
      _scanProgress = 0;
      _scanTotal = 0;
      _scanBytes = 0;
      _scanCurrentName = '';
      _lastResults = [];
    });
    var scanned = 0;
    var findingCount = 0;
    var errorCount = 0;
    final findings = <FileScanResult>[];
    try {
      await for (final entry in _saf.walk(uri)) {
        if (_cancelScan) break;
        if (entry.file.isDir) continue;
        scanned++;
        if (mounted) {
          setState(() {
            _scanProgress = scanned;
            _scanCurrentName = entry.relativePath;
            _scanBytes = 0;
          });
        }
        final relativePath = entry.relativePath;
        FileScanResult result;
        try {
          final content = await _saf.readFileStream(
            entry.file.uri,
            bufferSize: 64 * 1024,
          );
          result = await FileScanner.scan(
            name: relativePath,
            content: content,
            knownHashes: _knownHashes,
            onProgress: (bytes) {
              if (mounted) setState(() => _scanBytes = bytes);
            },
            isCancelled: () => _cancelScan,
          );
        } on ScanCancelledException {
          scanned--;
          break;
        } catch (error) {
          errorCount++;
          result = FileScanResult(
            name: relativePath,
            sha256: '',
            bytes: 0,
            scannedAt: DateTime.now(),
            level: FindingLevel.clean,
            reasons: [tr('scanError', {'error': error.toString()})],
            complete: false,
          );
        }
        _history.insert(0, result);
        if (_history.length > 50) _history.removeRange(50, _history.length);
        if (scanned % 10 == 0) await _saveHistory();
        if (result.level != FindingLevel.clean || !result.complete) {
          findingCount++;
          if (findings.length < 50) findings.add(result);
        }
      }
      if (!mounted) return;
      setState(() {
        _lastResults = findings;
        _scanning = false;
        _scanTotal = 0;
        _scanBytes = 0;
      });
      await _saveHistory();
      _message(_cancelScan
          ? tr('scanStopped', {'count': '$scanned'})
          : tr('folderScanDone', {
              'count': '$scanned',
              'findings': '$findingCount',
              'errors': '$errorCount',
            }));
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _scanning = false;
        _scanTotal = 0;
        _scanBytes = 0;
      });
      await _saveHistory();
      _message(tr('folderScanError', {
        'error': '$folderName: $error',
      }));
    }
  }

  void _stopScan() {
    if (!_scanning) return;
    setState(() => _cancelScan = true);
  }

  Future<void> _importHashes() async {
    try {
      final file = await FilePicker.pickFile(
        type: FileType.custom,
        allowedExtensions: ['txt', 'csv'],
      );
      if (file == null) return;
      final imported = <String>{};
      final lines = const LineSplitter()
          .bind(utf8.decoder.bind(file.readAsByteStream()));
      await for (final line in lines) {
        imported.addAll(parseSha256List(line));
        if (imported.length > 5000) {
          _message(tr('hashLimit'));
          return;
        }
      }
      if (imported.isEmpty) {
        _message(tr('hashImportEmpty'));
        return;
      }
      final updated = {..._knownHashes, ...imported};
      if (updated.length > 5000) {
        _message(tr('hashLimit'));
        return;
      }
      await _preferences.setStringList('known_hashes', updated.toList());
      if (!mounted) return;
      setState(() => _knownHashes = updated);
      _message(tr('hashImportSuccess', {'count': '${imported.length}'}));
    } catch (error) {
      if (!mounted) return;
      _message(tr('importError', {'error': error.toString()}));
    }
  }

  Future<void> _changeLanguage(String language) async {
    await _preferences.setString('language', language);
    if (!mounted) return;
    setState(() => _language = language);
    _message(tr('languageSaved'));
  }

  void _message(String value) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(value)));
  }

  @override
  Widget build(BuildContext context) {
    final colors = ColorScheme.fromSeed(
      seedColor: const Color(0xff22d3a8),
      brightness: Brightness.dark,
      surface: const Color(0xff0e1520),
    );
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Luna Guard',
      theme: ThemeData(
        colorScheme: colors,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xff070b12),
        cardTheme: CardThemeData(
          color: const Color(0xff0e1520),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
            side: const BorderSide(color: Color(0xff1a2535)),
          ),
        ),
      ),
      home: _buildHome(),
    );
  }

  Widget _buildHome() {
    final titles = [tr('scan'), tr('history'), tr('guide'), tr('settings')];
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: Row(
          children: [
            ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Image.asset('assets/Luna_Guard.png',
                  width: 42, height: 42, fit: BoxFit.cover),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Luna Guard',
                      style:
                          TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
                  Text(tr('tagline'),
                      style: Theme.of(context).textTheme.labelSmall),
                ],
              ),
            ),
          ],
        ),
        actions: [
          PopupMenuButton<String>(
            tooltip: tr('language'),
            icon: const Icon(Icons.language),
            onSelected: _changeLanguage,
            itemBuilder: (context) => const [
              PopupMenuItem(value: 'th', child: Text('ไทย')),
              PopupMenuItem(value: 'en', child: Text('English')),
              PopupMenuItem(value: 'zh-CN', child: Text('简体中文')),
            ],
          ),
        ],
      ),
      body: !_ready
          ? const Center(child: CircularProgressIndicator())
          : _loadError != null
              ? Center(child: Text(_loadError!))
              : IndexedStack(
                  index: _tab,
                  children: [
                    _scanPage(),
                    _historyPage(),
                    _guidePage(),
                    _settingsPage(),
                  ],
                ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (index) => setState(() => _tab = index),
        destinations: [
          NavigationDestination(
              icon: const Icon(Icons.shield_outlined),
              selectedIcon: const Icon(Icons.shield),
              label: titles[0]),
          NavigationDestination(
              icon: const Icon(Icons.history), label: titles[1]),
          NavigationDestination(
              icon: const Icon(Icons.menu_book_outlined), label: titles[2]),
          NavigationDestination(
              icon: const Icon(Icons.settings_outlined), label: titles[3]),
        ],
      ),
    );
  }

  Widget _scanPage() => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _panel(
            icon: Icons.shield_moon_outlined,
            title: tr('scanTitle'),
            body: tr(Platform.isAndroid ? 'scanInfoAndroid' : 'scanInfo'),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                FilledButton.icon(
                  onPressed: _scanning ? null : _selectAndScan,
                  icon: _scanning
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.folder_open),
                  label: Text(_scanning ? tr('scanning') : tr('pickFiles')),
                ),
                if (Platform.isAndroid) ...[
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: _scanning ? null : _scanSavedAutoFolder,
                    icon: const Icon(Icons.folder_special_outlined),
                    label: Text(_autoScanFolderUri == null
                        ? tr('scanFolder')
                        : tr('scanSavedFolder', {
                            'folder': _autoScanFolderName ?? '',
                          })),
                  ),
                  if (_autoScanFolderUri != null)
                    TextButton(
                      onPressed: _scanning ? null : _pickAutoScanFolder,
                      child: Text(tr('changeFolder')),
                    ),
                ],
                if (_scanning) ...[
                  const SizedBox(height: 12),
                  LinearProgressIndicator(
                    value:
                        _scanTotal == 0 ? null : _scanProgress / _scanTotal,
                  ),
                  const SizedBox(height: 8),
                  Text(_scanTotal == 0
                      ? tr('folderProgress', {
                          'count': '$_scanProgress',
                          'name': _scanCurrentName,
                          'bytes': '$_scanBytes',
                        })
                      : tr('scanProgressBytes', {
                          'current': '$_scanProgress',
                          'total': '$_scanTotal',
                          'bytes': '$_scanBytes',
                        })),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: _stopScan,
                    icon: const Icon(Icons.stop_circle_outlined),
                    label: Text(tr('stopScan')),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 12),
          _panel(
            icon: Icons.info_outline,
            title: tr('privacyTitle'),
            body: tr('privacyInfo'),
            color: const Color(0xfffbbf24),
          ),
          if (_lastResults.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text(tr('history'),
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            ..._lastResults.map(_resultCard),
          ],
        ],
      );

  Widget _historyPage() {
    if (_history.isEmpty) {
      return Center(child: Text(tr('noHistory')));
    }
    return ListView(
      padding: const EdgeInsets.all(16),
      children: _history.map(_resultCard).toList(),
    );
  }

  Widget _resultCard(FileScanResult result) {
    final color = switch (result.level) {
      FindingLevel.high => const Color(0xfff87171),
      FindingLevel.medium => const Color(0xfffbbf24),
      FindingLevel.low => const Color(0xff38bdf8),
      FindingLevel.clean => result.complete
          ? const Color(0xff34d399)
          : const Color(0xfffbbf24),
    };
    final label = switch (result.level) {
      FindingLevel.high => tr('high'),
      FindingLevel.medium => tr('medium'),
      FindingLevel.low => tr('low'),
      FindingLevel.clean =>
        result.complete ? tr('clean') : tr('scanIncomplete'),
    };
    return Card(
      child: ExpansionTile(
        leading: Icon(
          result.level == FindingLevel.high
              ? Icons.warning_amber_rounded
              : result.complete
                  ? Icons.check_circle_outline
                  : Icons.error_outline,
          color: color,
        ),
        title: Text(result.name, maxLines: 2, overflow: TextOverflow.ellipsis),
        subtitle: Text(
          '${result.scannedAt.toLocal().toString().split('.').first} · $label',
          style: TextStyle(color: color),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: SelectableText(
              '${tr('filePath')}: ${result.name}\n'
              '${tr('fileSize')}: ${result.bytes} ${tr('bytes')}',
            ),
          ),
          if (result.sha256.isNotEmpty)
            SelectableText('${tr('hash')}: ${result.sha256}'),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: Text(tr('why'),
                style: const TextStyle(fontWeight: FontWeight.bold)),
          ),
          for (final reason in result.reasons)
            Align(
              alignment: Alignment.centerLeft,
              child: Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('• ${tr(reason)}'),
              ),
            ),
        ],
      ),
    );
  }

  Widget _guidePage() => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _panel(
            icon: Icons.touch_app_outlined,
            title: tr('scanTitle'),
            body: tr('guideText'),
          ),
          const SizedBox(height: 12),
          _panel(
            icon: Icons.warning_amber_rounded,
            title: tr('privacyTitle'),
            body: tr('guideLimits'),
            color: const Color(0xfffbbf24),
          ),
          const SizedBox(height: 12),
          _panel(
            icon: Icons.privacy_tip_outlined,
            title: 'Luna Guard',
            body: tr('threatNotice'),
          ),
        ],
      );

  Widget _settingsPage() => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _panel(
            icon: Icons.fingerprint,
            title: tr('hashTitle'),
            body: '${tr('hashInfo')}\n\n${_knownHashes.length} SHA-256',
            child: OutlinedButton.icon(
              onPressed: _importHashes,
              icon: const Icon(Icons.file_upload_outlined),
              label: Text(tr('importHashes')),
            ),
          ),
        ],
      );

  Widget _panel({
    required IconData icon,
    required String title,
    required String body,
    Color? color,
    Widget? child,
  }) =>
      Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(icon, color: color ?? const Color(0xff22d3a8)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(title,
                        style: Theme.of(context).textTheme.titleMedium),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Text(body,
                  style: TextStyle(
                      color: Theme.of(context).colorScheme.onSurfaceVariant)),
              if (child != null) ...[
                const SizedBox(height: 16),
                SizedBox(width: double.infinity, child: child),
              ],
            ],
          ),
        ),
      );
}
