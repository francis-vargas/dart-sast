// tests/samples/vulnerable_app.dart
// ⚠️  INTENTIONALLY VULNERABLE — for dart_sast testing only.
// Do NOT use this code in production.

import 'dart:math';
import 'dart:io';
import 'package:sqflite/sqflite.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http;
import 'dart:io' show HttpClient;

// DART-SEC-001: Hardcoded credentials
const String apiKey = "sk-prod-1234567890abcdef";
const String dbPassword = "super_secret_pass";

// DART-SEC-002: Insecure HTTP
final String serverUrl = "http://api.myapp.com/v1/data";

// DART-SEC-003: Weak crypto (MD5)
import 'package:crypto/crypto.dart';
String hashPassword(String pw) => md5.convert(utf8.encode(pw)).toString();

// DART-SEC-004: Non-secure Random
String generateToken() {
  final rand = Random();
  return rand.nextInt(999999).toString();
}

// DART-SEC-005: SQL Injection
Future<List<Map>> getUser(Database db, String username) async {
  return db.rawQuery("SELECT * FROM users WHERE name = '$username'");
}

// DART-SEC-006: Logging sensitive data
void loginUser(String password) {
  print("User password: $password");
  debugPrint("token: $password");
}

// DART-SEC-007: Debug mode enabled
void initApp() {
  bool debugMode = true;
}

// DART-SEC-008: Sensitive data in SharedPreferences
Future<void> saveToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString("auth_token", token);
}

// DART-SEC-009: Certificate validation disabled
HttpClient createInsecureClient() {
  return HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
}

// DART-SEC-010: Path traversal
Future<String> readFile(String userInput) async {
  final f = File('/data/$userInput');
  return f.readAsString();
}