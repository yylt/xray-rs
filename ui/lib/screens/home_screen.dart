import 'package:flutter/material.dart';

import '../constants/app_colors.dart';
import '../services/core_service.dart';
import 'placeholder_settings_screen.dart';
import 'routing_settings_screen.dart';
import 'subscription_settings_screen.dart';

enum ConnectionStatus { disconnected, connecting, connected }

class Node {
  const Node({required this.name, required this.latencyMs});

  final String name;
  final int latencyMs;
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final CoreService _coreService = CoreService();
  final List<Node> _nodes = [
    const Node(name: 'JP-01 Tokyo', latencyMs: 86),
    const Node(name: 'SG-02 Singapore', latencyMs: 102),
    const Node(name: 'US-03 Los Angeles', latencyMs: 168),
  ];

  ConnectionStatus _status = ConnectionStatus.disconnected;
  int _selectedNodeIndex = 0;
  double _upRate = 0;
  double _downRate = 0;

  Node? get _selectedNode => _nodes.isEmpty ? null : _nodes[_selectedNodeIndex];

  @override
  void initState() {
    super.initState();
    _coreService.startOnLaunch();
  }

  Future<void> _toggleConnection() async {
    if (_status == ConnectionStatus.connecting) {
      return;
    }

    if (_status == ConnectionStatus.disconnected) {
      setState(() {
        _status = ConnectionStatus.connecting;
      });

      await Future<void>.delayed(const Duration(milliseconds: 600));
      if (!mounted) {
        return;
      }

      setState(() {
        _status = ConnectionStatus.connected;
        _upRate = 1.2;
        _downRate = 8.6;
      });
      return;
    }

    setState(() {
      _status = ConnectionStatus.disconnected;
      _upRate = 0;
      _downRate = 0;
    });
  }

  void _showSystemSettings() {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (context) {
        return DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.4,
          minChildSize: 0.4,
          maxChildSize: 0.4,
          builder: (context, scrollController) {
            return ListView(
              controller: scrollController,
              children: [
                const ListTile(title: Text('系统设置')),
                _settingsItem('订阅设置'),
                _settingsItem('应用设置'),
                _settingsItem('路由设置'),
                _settingsItem('系统'),
                _settingsItem('日志'),
              ],
            );
          },
        );
      },
    );
  }

  Widget _settingsItem(String title) {
    return ListTile(
      title: Text(title),
      trailing: const Icon(Icons.chevron_right),
      onTap: () {
        Navigator.of(context).pop();
        _openSettingsPage(title);
      },
    );
  }

  void _openSettingsPage(String title) {
    Widget page;
    switch (title) {
      case '订阅设置':
        page = const SubscriptionSettingsScreen();
      case '路由设置':
        page = const RoutingSettingsScreen();
      default:
        page = PlaceholderSettingsScreen(title: title);
    }

    Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (context) => page));
  }

  void _showActionMessage(String text) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          key: const Key('settings_button'),
          icon: const Icon(Icons.settings),
          onPressed: _showSystemSettings,
        ),
        title: Text(
          _selectedNode == null
              ? '未选择节点 (--ms)'
              : '${_selectedNode!.name} (${_selectedNode!.latencyMs}ms)',
        ),
        actions: [
          IconButton(
            key: const Key('search_button'),
            icon: const Icon(Icons.search),
            onPressed: () => _openSettingsPage('节点搜索'),
          ),
          PopupMenuButton<String>(
            key: const Key('add_menu_button'),
            icon: const Icon(Icons.add),
            onSelected: (value) => _showActionMessage(value),
            itemBuilder: (context) => const [
              PopupMenuItem(value: '扫码添加（占位）', child: Text('扫码添加')),
              PopupMenuItem(value: '手动输入（占位）', child: Text('手动输入')),
              PopupMenuItem(value: '从剪贴板导入（占位）', child: Text('从剪贴板导入')),
            ],
          ),
        ],
      ),
      body: ListView.builder(
        itemCount: _nodes.length,
        itemBuilder: (context, index) {
          final node = _nodes[index];
          final isSelected = index == _selectedNodeIndex;
          return Dismissible(
            key: ValueKey(node.name),
            direction: DismissDirection.endToStart,
            onDismissed: (_) {
              setState(() {
                _nodes.removeAt(index);
                if (_selectedNodeIndex >= _nodes.length) {
                  _selectedNodeIndex = _nodes.isEmpty ? 0 : _nodes.length - 1;
                }
              });
              _showActionMessage('已删除 ${node.name}');
            },
            background: Container(
              color: Colors.red,
              alignment: Alignment.centerRight,
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: const Icon(Icons.delete, color: Colors.white),
            ),
            child: ListTile(
              key: Key('node_$index'),
              tileColor: isSelected
                  ? Theme.of(context).colorScheme.primaryContainer
                  : null,
              title: Text(node.name),
              subtitle: Text('延迟 ${node.latencyMs}ms'),
              trailing: isSelected
                  ? const Icon(Icons.check_circle, color: Colors.green)
                  : null,
              onTap: () {
                setState(() {
                  _selectedNodeIndex = index;
                });
              },
              onLongPress: () => _showActionMessage('编辑 ${node.name}（占位）'),
            ),
          );
        },
      ),
      floatingActionButton: FloatingActionButton.extended(
        key: const Key('connect_fab'),
        onPressed: _toggleConnection,
        backgroundColor: switch (_status) {
          ConnectionStatus.disconnected => AppColors.connect,
          ConnectionStatus.connecting => AppColors.connecting,
          ConnectionStatus.connected => AppColors.disconnect,
        },
        icon: switch (_status) {
          ConnectionStatus.disconnected => const Icon(Icons.power_settings_new),
          ConnectionStatus.connecting => const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          ConnectionStatus.connected => const Icon(Icons.stop_circle_outlined),
        },
        label: Text(switch (_status) {
          ConnectionStatus.disconnected => '点击连接',
          ConnectionStatus.connecting => '连接中...',
          ConnectionStatus.connected =>
            '断开连接  ↑${_upRate.toStringAsFixed(1)} ↓${_downRate.toStringAsFixed(1)} MB/s',
        }),
      ),
    );
  }
}
