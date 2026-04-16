import 'package:flutter/material.dart';

class PlaceholderSettingsScreen extends StatelessWidget {
  const PlaceholderSettingsScreen({super.key, required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: Center(child: Text('$title（占位页面）')),
    );
  }
}
