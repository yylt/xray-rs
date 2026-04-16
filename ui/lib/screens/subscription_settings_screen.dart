import 'package:flutter/material.dart';

class SubscriptionSettingsScreen extends StatefulWidget {
  const SubscriptionSettingsScreen({super.key});

  @override
  State<SubscriptionSettingsScreen> createState() =>
      _SubscriptionSettingsScreenState();
}

class _SubscriptionSettingsScreenState extends State<SubscriptionSettingsScreen> {
  final TextEditingController _urlController = TextEditingController();
  final List<_SubscriptionItem> _items = [];

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  void _addUrl() {
    final url = _urlController.text.trim();
    if (url.isEmpty) {
      return;
    }

    setState(() {
      _items.add(_SubscriptionItem(url: url, updatedAt: DateTime.now()));
      _urlController.clear();
    });
  }

  void _updateAll() {
    final now = DateTime.now();
    setState(() {
      for (var i = 0; i < _items.length; i++) {
        _items[i] = _SubscriptionItem(url: _items[i].url, updatedAt: now);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('订阅设置')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('订阅 URL 管理', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            TextField(
              key: const Key('subscription_url_input'),
              controller: _urlController,
              decoration: const InputDecoration(
                labelText: '订阅 URL',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                ElevatedButton(
                  key: const Key('add_subscription_url_button'),
                  onPressed: _addUrl,
                  child: const Text('添加订阅'),
                ),
                const SizedBox(width: 12),
                OutlinedButton(onPressed: _updateAll, child: const Text('手动更新')),
              ],
            ),
            const SizedBox(height: 12),
            Expanded(
              child: _items.isEmpty
                  ? const Center(child: Text('暂无订阅 URL'))
                  : ListView.builder(
                      itemCount: _items.length,
                      itemBuilder: (context, index) {
                        final item = _items[index];
                        return ListTile(
                          title: Text(item.url),
                          subtitle: Text('最后更新 ${_formatDateTime(item.updatedAt)}'),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }

  String _formatDateTime(DateTime time) {
    final month = time.month.toString().padLeft(2, '0');
    final day = time.day.toString().padLeft(2, '0');
    final hour = time.hour.toString().padLeft(2, '0');
    final minute = time.minute.toString().padLeft(2, '0');
    return '$month-$day $hour:$minute';
  }
}

class _SubscriptionItem {
  const _SubscriptionItem({required this.url, required this.updatedAt});

  final String url;
  final DateTime updatedAt;
}
