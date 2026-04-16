import 'dart:io';

import 'package:path_provider/path_provider.dart';

class RuleDownloadResult {
  const RuleDownloadResult({required this.domainPath, required this.cidrPath});

  final String domainPath;
  final String cidrPath;
}

class RuleFileService {
  const RuleFileService();

  Future<RuleDownloadResult> downloadAndSave({
    required String domainUrl,
    required String cidrUrl,
  }) async {
    final appDir = await getApplicationDocumentsDirectory();
    final ruleDir = Directory('${appDir.path}/rules');
    if (!await ruleDir.exists()) {
      await ruleDir.create(recursive: true);
    }

    final domainContent = await _downloadText(domainUrl);
    final cidrContent = await _downloadText(cidrUrl);

    final domainFile = File('${ruleDir.path}/domain.txt');
    final cidrFile = File('${ruleDir.path}/cidr.txt');

    await domainFile.writeAsString(domainContent);
    await cidrFile.writeAsString(cidrContent);

    return RuleDownloadResult(
      domainPath: domainFile.path,
      cidrPath: cidrFile.path,
    );
  }

  Future<String> _downloadText(String url) async {
    final client = HttpClient();
    try {
      final request = await client.getUrl(Uri.parse(url));
      final response = await request.close();
      if (response.statusCode != 200) {
        throw Exception('download failed: $url (${response.statusCode})');
      }
      return response.transform(SystemEncoding().decoder).join();
    } finally {
      client.close(force: true);
    }
  }
}
