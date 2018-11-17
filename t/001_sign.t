#!/usr/bin/perl

use strict;
use warnings;
use bytes;
use Test::More tests => 12;
use File::Temp qw/tempdir/;
use File::Path qw/remove_tree make_path/;
use Digest::SHA;
use FindBin;

my $user     = 'defaultkey@localobs';
my $prj_user = 'signd@localhost';
my $comment  = "just for testing";
my $tmp_dir  = "$FindBin::Bin/tmp";
my $var_dir  = "$tmp_dir/var";
my $fixtures_dir = "$FindBin::Bin/fixtures";
my $payload  = "test";

###############################################################################
### Prepare tests
remove_tree($tmp_dir);

make_path($var_dir);
$ENV{SIGND_VAR} = $var_dir;
$ENV{LANG} = 'C';
my $gnupghome=$ENV{GNUPGHOME};
$ENV{GNUPGHOME} = "$tmp_dir/gnupg";
make_path($ENV{GNUPGHOME});
chmod 0700, $ENV{GNUPGHOME};
system("gpg -q --import $fixtures_dir/secret-key.asc");

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

my $tmpdir = "$tmp_dir/tmp";
mkdir($tmpdir, 0700);

my $sign = "./sign --test-sign ./signd";

###############################################################################
### if ($cmd eq 'ping') {
my $ping_result = `$sign -t`;
is($?, 0, "Checking cmd 'ping' return code");

###############################################################################
### if ($cmd eq 'pubkey') {
my $pubkey_result = `$sign -p`;
is($?, 0, "Checking cmd 'pubkey' return code");
my $expected = slurp("$fixtures_dir/public-key.asc");
my @got = split(/\n/, $pubkey_result);
splice(@got, 1, 1) if ($got[1] eq 'Version: GnuPG v2');
my $clean_got = join("\n", @got) . "\n";
is($clean_got, $expected, "Checking exported pubkey");

###############################################################################
### if ($cmd eq 'keygen') {
my $pubkey = `$sign -P $tmpdir/P -g "rsa\@2048" 800 "$comment" $prj_user`;
is($?, 0, "Checking cmd 'keygen' return code");

spew("$tmpdir/p", $pubkey);
system("gpg -q --import $tmpdir/p");
is($?, 0, "Checking pubkey import return code");

###############################################################################
### if ($cmd eq 'certgen') {
my $cert = `$sign -P $tmpdir/P -C $tmpdir/p`;
is($?, 0, "Checking cmd 'certgen' return code");
my $end_cert = qr/-----END CERTIFICATE-----$/;
like($cert, $end_cert, "Checking for end of certificate");
spew("$tmpdir/c", $cert);
my $openssl_verify = `openssl verify -check_ss_sig -CAfile $tmpdir/c $tmpdir/c`;
is($?, 0, "Checking openssl verify return code");

###############################################################################
### if ($cmd eq 'privsign') {
spew("$tmpdir/privsign", $payload);
my $privsign_result = `$sign -P $tmpdir/P -d $tmpdir/privsign`;

is($?, 0, "Checking cmd 'privsign' return code");
my $verify_privsign = `gpg --verify $tmpdir/privsign.asc 2>&1`;
like($verify_privsign, qr/Good signature from/, "Checking cmd 'privsign' for 'Good signature'");

###############################################################################
### if ($cmd eq 'sign') {
spew("$tmpdir/sign", $payload);
my $sign_result = `$sign -d $tmpdir/sign`;
is($?, 0, "Checking cmd 'sign' return code");
my $verify_sign = `gpg --verify $tmpdir/sign.asc 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking for 'Good signature'");

###############################################################################
### cleanup
exit 0;
remove_tree($tmp_dir);
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

