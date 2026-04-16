import 'dart:convert';
import 'dart:io';

class ApiService {
  const ApiService();

  Future<Map<String, dynamic>> getStats() async {
    final client = HttpClient();
    try {
      final request = await client.getUrl(Uri.parse('http://127.0.0.1:10085/stats'));
      final response = await request.close();
      if (response.statusCode != 200) {
        throw Exception('stats request failed: ${response.statusCode}');
      }

      final body = await response.transform(utf8.decoder).join();
      return jsonDecode(body) as Map<String, dynamic>;
    } finally {
      client.close(force: true);
    }
  }
}
