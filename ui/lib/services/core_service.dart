import 'dart:io';

import '../utils/logger.dart';

class CoreService {
  CoreService({this.executablePath = 'core'});

  final String executablePath;
  Process? _process;

  Future<void> startOnLaunch() async {
    if (_process != null) {
      return;
    }

    try {
      _process = await Process.start(executablePath, const []);
      AppLogger.info('core started: $executablePath');
      _process?.stdout.transform(SystemEncoding().decoder).listen(AppLogger.info);
      _process?.stderr.transform(SystemEncoding().decoder).listen(AppLogger.error);
    } catch (e) {
      AppLogger.error('core start failed: $e');
    }
  }

  Future<void> stop() async {
    _process?.kill();
    _process = null;
  }
}
