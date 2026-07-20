<?php
/**
 * Locke-NG Contact Form Mailer
 * Deployment: cPanel / topservice.ng
 * Recipient: info@locke-ng.com
 * Security: CSRF token, honeypot, input sanitization, rate limiting
 */

// ─── Configuration ───────────────────────────────────────────
define('RECIPIENT_EMAIL', 'info@locke-ng.com');
define('RECIPIENT_NAME',  'Locke NG');
define('SITE_NAME',       'Locke-NG');
define('RATE_LIMIT_MAX',  3);     // Max submissions per window
define('RATE_LIMIT_TTL',  3600);  // Window in seconds (1 hour)

// ─── Bootstrap ───────────────────────────────────────────────
session_start();
header('Content-Type: application/json');

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
    exit;
}

// ─── CSRF Validation ─────────────────────────────────────────
if (
    empty($_POST['csrf_token']) ||
    empty($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Invalid request token.']);
    exit;
}

// Regenerate CSRF token after use
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// ─── Honeypot Check ──────────────────────────────────────────
// Bots fill hidden fields; humans leave them empty
if (!empty($_POST['website'])) {
    http_response_code(200); // Return 200 to confuse bots
    echo json_encode(['success' => true, 'message' => 'Message sent.']);
    exit;
}

// ─── Rate Limiting ───────────────────────────────────────────
$ip  = $_SERVER['REMOTE_ADDR'];
$key = 'rate_' . md5($ip);

if (!isset($_SESSION[$key])) {
    $_SESSION[$key] = ['count' => 0, 'start' => time()];
}

if ((time() - $_SESSION[$key]['start']) > RATE_LIMIT_TTL) {
    $_SESSION[$key] = ['count' => 0, 'start' => time()];
}

if ($_SESSION[$key]['count'] >= RATE_LIMIT_MAX) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'message' => 'Too many submissions. Please try again later.'
    ]);
    exit;
}

$_SESSION[$key]['count']++;

// ─── Input Sanitization ──────────────────────────────────────
$name    = htmlspecialchars(strip_tags(trim($_POST['name']    ?? '')));
$email   = htmlspecialchars(strip_tags(trim($_POST['email']   ?? '')));
$phone   = htmlspecialchars(strip_tags(trim($_POST['phone']   ?? '')));
$subject = htmlspecialchars(strip_tags(trim($_POST['subject'] ?? '')));
$message = htmlspecialchars(strip_tags(trim($_POST['message'] ?? '')));

// ─── Validation ──────────────────────────────────────────────
$errors = [];

if (empty($name) || strlen($name) < 2) {
    $errors[] = 'Please enter your full name.';
}
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Please enter a valid email address.';
}
if (empty($message) || strlen($message) < 10) {
    $errors[] = 'Please enter a message (minimum 10 characters).';
}
if (strlen($name) > 100 || strlen($subject) > 200 || strlen($message) > 5000) {
    $errors[] = 'Input exceeds allowed length.';
}

if (!empty($errors)) {
    http_response_code(422);
    echo json_encode(['success' => false, 'message' => implode(' ', $errors)]);
    exit;
}

// ─── Send Email via PHPMailer + SMTP ─────────────────────────
require_once __DIR__ . '/vendor/phpmailer/PHPMailer.php';
require_once __DIR__ . '/vendor/phpmailer/SMTP.php';
require_once __DIR__ . '/vendor/phpmailer/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);

try {
    // SMTP Configuration for cPanel
    $mail->isSMTP();
    $mail->Host       = 'mail.locke-ng.com';   // cPanel mail server
    $mail->SMTPAuth   = true;
    $mail->Username   = 'noreply@locke-ng.com'; // Sending account in cPanel
    $mail->Password   = 'REPLACE_WITH_EMAIL_PASSWORD';
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->Port       = 465;

    // Recipients
    $mail->setFrom('noreply@locke-ng.com', SITE_NAME . ' Website');
    $mail->addAddress(RECIPIENT_EMAIL, RECIPIENT_NAME);
    $mail->addReplyTo($email, $name); // Reply goes to visitor

    // Content
    $mail->isHTML(false); // Plain text is safer and less likely to be flagged
    $mail->Subject = '[Locke-NG] ' . ($subject ?: 'New Contact Form Message');
    $mail->Body    = buildEmailBody($name, $email, $phone, $subject, $message);

    $mail->send();

    echo json_encode([
        'success' => true,
        'message' => 'Thank you! Your message has been received. We will be in touch shortly.'
    ]);

} catch (Exception $e) {
    http_response_code(500);
    // Log error server-side, never expose to user
    error_log('[Locke-NG Mailer Error] ' . $mail->ErrorInfo);
    echo json_encode([
        'success' => false,
        'message' => 'Sorry, we could not send your message. Please try again or email us directly at info@locke-ng.com.'
    ]);
}

// ─── Helper: Build Email Body ─────────────────────────────────
function buildEmailBody($name, $email, $phone, $subject, $message): string
{
    $timestamp = date('Y-m-d H:i:s T');
    return <<<EOT
New Contact Form Submission
===========================

Name:    $name
Email:   $email
Phone:   $phone
Subject: $subject

Message:
--------
$message

---
Submitted: $timestamp
Source:    Locke-NG Website Contact Form
EOT;
}
