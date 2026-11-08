// Synthetic Dart sample for Longinus defensive static auditing
class SessionStore {
  Future<void> saveSession(dynamic prefs, dynamic httpClient, String jwt) async {
    httpClient.badCertificateCallback = (cert, host, port) => true;
    await prefs.setString('session_secret_token', jwt);
  }
}
