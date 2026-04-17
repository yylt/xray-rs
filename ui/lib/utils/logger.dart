import 'package:flutter/foundation.dart';

class AppLogger {
  static void info(String message) => debugPrint('[INFO] $message');

  static void error(String message) => debugPrint('[ERROR] $message');
}
