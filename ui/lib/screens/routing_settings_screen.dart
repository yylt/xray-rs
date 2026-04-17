import 'package:flutter/material.dart';

import '../services/rule_file_service.dart';

class RoutingSettingsScreen extends StatefulWidget {
  const RoutingSettingsScreen({super.key});

  @override
  State<RoutingSettingsScreen> createState() => _RoutingSettingsScreenState();
}

class _RoutingSettingsScreenState extends State<RoutingSettingsScreen> {
  final RuleFileService _ruleFileService = const RuleFileService();
  final TextEditingController _domainController = TextEditingController();
  final TextEditingController _cidrController = TextEditingController();

  bool _customRoutingEnabled = false;
  bool _isDownloading = false;
  String? _domainPath;
  String? _cidrPath;

  @override
  void dispose() {
    _domainController.dispose();
    _cidrController.dispose();
    super.dispose();
  }

  Future<void> _downloadRules() async {
    final domainUrl = _domainController.text.trim();
    final cidrUrl = _cidrController.text.trim();
    if (domainUrl.isEmpty || cidrUrl.isEmpty) {
      return;
    }

    setState(() {
      _isDownloading = true;
    });

    try {
      final result = await _ruleFileService.downloadAndSave(
        domainUrl: domainUrl,
        cidrUrl: cidrUrl,
      );

      if (!mounted) {
        return;
      }

      setState(() {
        _domainPath = result.domainPath;
        _cidrPath = result.cidrPath;
      });

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('规则库更新完成')),
      );
    } catch (e) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('规则库更新失败: $e')));
    } finally {
      if (mounted) {
        setState(() {
          _isDownloading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('路由设置')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: ListView(
          children: [
            Text('规则文件源', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            TextField(
              key: const Key('domain_url_input'),
              controller: _domainController,
              decoration: const InputDecoration(
                labelText: 'Domain List URL',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('cidr_url_input'),
              controller: _cidrController,
              decoration: const InputDecoration(
                labelText: 'CIDR List URL',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              key: const Key('update_rules_button'),
              onPressed: _isDownloading ? null : _downloadRules,
              child: Text(_isDownloading ? '更新中...' : '更新规则库'),
            ),
            const SizedBox(height: 12),
            if (_domainPath != null)
              Text('domain.txt: $_domainPath', key: const Key('domain_path_text')),
            if (_cidrPath != null)
              Text('cidr.txt: $_cidrPath', key: const Key('cidr_path_text')),
            const SizedBox(height: 12),
            SwitchListTile(
              key: const Key('custom_routing_switch'),
              title: const Text('启用自定义路由规则'),
              value: _customRoutingEnabled,
              onChanged: (value) {
                setState(() {
                  _customRoutingEnabled = value;
                });
              },
            ),
          ],
        ),
      ),
    );
  }
}
