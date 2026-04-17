import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:ui/main.dart';

void main() {
  testWidgets('renders home skeleton from PRD', (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());

    expect(find.byKey(const Key('settings_button')), findsOneWidget);
    expect(find.byKey(const Key('search_button')), findsOneWidget);
    expect(find.byKey(const Key('add_menu_button')), findsOneWidget);
    expect(find.byKey(const Key('connect_fab')), findsOneWidget);
    expect(find.byKey(const Key('node_0')), findsOneWidget);
    expect(find.text('点击连接'), findsOneWidget);
  });

  testWidgets('fab switches from disconnected to connected', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const MyApp());

    await tester.tap(find.byKey(const Key('connect_fab')));
    await tester.pump();
    expect(find.text('连接中...'), findsOneWidget);

    await tester.pump(const Duration(milliseconds: 700));
    expect(find.textContaining('断开连接'), findsOneWidget);
  });

  testWidgets('subscription settings page supports url management', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const MyApp());

    await tester.tap(find.byKey(const Key('settings_button')));
    await tester.pumpAndSettle();

    await tester.tap(find.text('订阅设置'));
    await tester.pumpAndSettle();

    expect(find.text('订阅 URL 管理'), findsOneWidget);
    expect(find.byKey(const Key('subscription_url_input')), findsOneWidget);
    expect(
      find.byKey(const Key('add_subscription_url_button')),
      findsOneWidget,
    );

    await tester.enterText(
      find.byKey(const Key('subscription_url_input')),
      'https://example.com/sub',
    );
    await tester.tap(find.byKey(const Key('add_subscription_url_button')));
    await tester.pumpAndSettle();

    expect(find.text('https://example.com/sub'), findsOneWidget);
    expect(find.textContaining('最后更新'), findsOneWidget);
  });

  testWidgets('routing settings page supports rule urls and toggle', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const MyApp());

    await tester.tap(find.byKey(const Key('settings_button')));
    await tester.pumpAndSettle();

    await tester.tap(find.text('路由设置'));
    await tester.pumpAndSettle();

    expect(find.text('规则文件源'), findsOneWidget);
    expect(find.byKey(const Key('domain_url_input')), findsOneWidget);
    expect(find.byKey(const Key('cidr_url_input')), findsOneWidget);

    final switchFinder = find.byKey(const Key('custom_routing_switch'));
    expect(switchFinder, findsOneWidget);

    await tester.tap(switchFinder);
    await tester.pumpAndSettle();

    final switchWidget = tester.widget<SwitchListTile>(switchFinder);
    expect(switchWidget.value, isTrue);
  });
}
