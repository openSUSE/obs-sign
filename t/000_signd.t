#!/usr/bin/perl

use strict;
use warnings;
use bytes;
use Test::More tests => 16;
use File::Temp qw/tempdir/;
use File::Path qw/remove_tree make_path/;
use Digest::SHA;
use FindBin;

my $user     = 'defaultkey@localobs';
my $usersec  = 'defaultkeysec@localobs';
my $prj_user = 'signd@localhost';
my $comment  = "just for testing";
my $tmp_dir  = "$FindBin::Bin/tmp";
my $var_dir  = "$tmp_dir/var";
my $fixtures_dir = "$FindBin::Bin/fixtures";

###############################################################################
### Prepare tests
remove_tree($tmp_dir);

make_path($var_dir);
$ENV{LANG} = 'C';
$ENV{GNUPGHOME} = "$tmp_dir/gnupg";
make_path($ENV{GNUPGHOME});
chmod 0700, $ENV{GNUPGHOME};
system("gpg -q --import $fixtures_dir/secret-key.asc");
if (system("gpg --pinentry-mode=loopback --version >/dev/null 2>&1 </dev/null") == 0)  {
  system("echo xxx | gpg -q --batch --pinentry-mode=loopback --passphrase-fd=0 --import $fixtures_dir/secret-key-passphrase.asc");
} else {
  system("echo xxx | gpg -q --batch --passphrase-fd=0 --import $fixtures_dir/secret-key-passphrase.asc");
}

my $sign_conf = "$tmp_dir/sign.conf";
$ENV{SIGN_CONF} = $sign_conf;
spew("$sign_conf", "user: $user
server: 127.0.0.1
tmpdir: $var_dir
allow: 127.0.0.1
phrases: $tmp_dir/gnupg/phrases
");

make_path("$tmp_dir/gnupg/phrases");
spew("$tmp_dir/gnupg/phrases/$user", '');
spew("$tmp_dir/gnupg/phrases/$usersec", 'xxx');

###############################################################################
### if ($cmd eq 'ping') {
my $ping_result = `./signd -t ping $user`;
is($?, 0, "Checking cmd 'ping' return code");

my @keys = decode_reply($ping_result);
###############################################################################
### if ($cmd eq 'pubkey') {
my $pubkey_result = `./signd -t pubkey $user`;
is($?, 0, "Checking cmd 'pubkey' return code");
my @out = decode_reply($pubkey_result);
my $expected = slurp("$fixtures_dir/public-key.asc");
my @got = split(/\n/, $out[0]);
splice(@got, 1, 1) if ($got[1] eq 'Version: GnuPG v2');
my $clean_got = join("\n", @got) . "\n";
is($clean_got, $expected, "Checking exported pubkey");

###############################################################################
### if ($cmd eq 'keygen') {
my $result = `./signd -t keygen $user "rsa\@2048" 800 "$comment" $prj_user`;
is($?, 0, "Checking cmd 'keygen' return code");
@keys = decode_reply($result);

my $privkey = pack("H*", $keys[1]);
my $tmpdir = "t/tmp";

( -d $tmpdir ) || mkdir($tmpdir, 0700);

my $tmppriv_encrypted = "$tmpdir/privkey_encrypted";
spew($tmppriv_encrypted, $privkey);
my $priv_decrypted = `gpg --batch --decrypt  $tmppriv_encrypted 2>/dev/null`;
is($?, 0 , "Checking if decryption was successful");
my $tmpgnupghome = tempdir("XXXXXXX", DIR => $tmpdir);

my $tmppriv_decrypted = "$tmpdir/privkey_decrypted";
$priv_decrypted .= pack('CC', 13 + 192, 8).'privsign';
spew($tmppriv_decrypted, $priv_decrypted);

$ENV{GNUPGHOME} = $tmpgnupghome;

my $importresult = `gpg --batch --allow-non-selfsigned-uid --import $tmppriv_decrypted 2>&1`;
is($?, 0, "Checking import of decrypted privkey");

$ENV{GNUPGHOME} = "$tmp_dir/gnupg";
###############################################################################
### if ($cmd eq 'certgen') {
my $cmd = "./signd -t certgen $user $keys[1] 800 \"$comment\" \"$prj_user\"";
my $certgen_result = `$cmd`;
is($?, 0, "Checking cmd 'certgen' return code");
my @certs = decode_reply($certgen_result, 1);
my $end_cert = qr/-----END CERTIFICATE-----$/;
like($certs[0], $end_cert, "Checking for end of certificate");


###############################################################################
### Common vars for sign and privsign
my $trailer = pack("CN", 0, time());
my $payload = "test";
my $arg = Digest::SHA::sha1_hex("$payload$trailer").'@'.unpack("H*", $trailer);

###############################################################################
### if ($cmd eq 'privsign') {
$cmd = "./signd -t privsign $user $keys[1] $arg";
my $privsign_result = `$cmd`;

is($?, 0, "Checking cmd 'privsign' return code");
my @privsign = decode_reply($privsign_result);
spew("$tmpdir/privsign", $payload);
spew("$tmpdir/privsign.sig", $privsign[0]);
$ENV{GNUPGHOME} = $tmpgnupghome;
my $verify_privsign = `gpg --allow-non-selfsigned-uid --verify $tmpdir/privsign.sig 2>&1`;
like(
  $verify_privsign,
  qr/Good signature from/,
  "Checking cmd 'privsign' for 'Good signature'"
);
$ENV{GNUPGHOME} = "$tmp_dir/gnupg";

my $expired_key = slurp("$FindBin::Bin/fixtures/secret-key-expired-encrypted");
chomp($expired_key);

$cmd = "./signd -t privsign $user $expired_key $arg";
#print "$cmd\n";
$privsign_result = `$cmd`;

is($?, 0, "Checking cmd 'privsign' return code (expired key)") || print $privsign_result;
@privsign = decode_reply($privsign_result);
spew("$tmpdir/privsign", $payload);
spew("$tmpdir/privsign.sig", $privsign[0]);
$ENV{GNUPGHOME} = $tmpgnupghome;
`gpg --import $FindBin::Bin/fixtures/public-key-expired.asc 2>&1`;
$verify_privsign = `gpg --verify $tmpdir/privsign.sig 2>&1`;
like(
  $verify_privsign,
  qr/Good signature from/,
  "Checking cmd 'privsign' for 'Good signature' (expired key)"
);

$ENV{GNUPGHOME} = "$tmp_dir/gnupg";



###############################################################################
### if ($cmd eq 'sign') {
my $sign_result = `./signd -t sign $user $arg`;
is($?, 0, "Checking cmd 'sign' return code");
my @sign = decode_reply($sign_result);
spew("$tmpdir/sign", $payload);
spew("$tmpdir/sign.sig", $sign[0]);
my $verify_sign = `gpg --verify $tmpdir/sign.sig 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking for 'Good signature'");

$sign_result = `./signd -t sign $usersec $arg`;
is($?, 0, "Checking cmd 'sign' return code");
@sign = decode_reply($sign_result);
spew("$tmpdir/sign", $payload);
spew("$tmpdir/sign.sig", $sign[0]);
$verify_sign = `gpg --verify $tmpdir/sign.sig 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking for 'Good signature'");

###############################################################################
### cleanup
remove_tree($tmpdir);
exit 0;

sub slurp {
  my ($fn) = @_;
  my $fh;
  open($fh, '<',  $fn) || die "Could not open '$fn': $!\n";
  local $/;
  my $content = <$fh>;
  close $fh;
  return $content;
}

sub spew {
  my ($fn, $content) = @_;
  my $fh;
  open($fh, '>',  $fn) || die "Could not open '$fn': $!\n";
  print $fh $content;
  close $fh;
}

sub decode_reply {
  my ($reply, $oldproto)  = @_;
  my @out_parts;
  my ($status, $l_out, $l_err) = unpack('nnn', $reply);
  my $out = substr($reply, 6, $l_out);
  my $err = substr($reply, 6 + $l_out, $l_err);
  die $err if $err;
  print "l_out: $l_out, l_err: $l_err\n" if $ENV{DEBUG};
  return () unless $l_out;

  return $out if $oldproto;

  my ($parts) = unpack('n',$out);
  print "parts: $parts\n" if $ENV{DEBUG};
  $out = substr($out, 2);
  my @pl = unpack('n' x $parts, $out);
  print "\@pl: (@pl)\n" if $ENV{DEBUG};
  $out = substr($out, 2 * $parts);
  for my $l (@pl) {
    my $t = substr($out, 0, $l);
    $out = substr($out, $l);
    push @out_parts, $t;
  }

  return @out_parts;
}
