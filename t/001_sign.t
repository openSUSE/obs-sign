#!/usr/bin/perl

use strict;
use warnings;
use bytes;
use Test::More tests => 36;
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
$ENV{LANG} = 'C';
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
my $result;

###############################################################################
### ping
$result = `$sign -t`;
is($?, 0, "Checking ping return code");

###############################################################################
### pubkey
$result = `$sign -p`;
is($?, 0, "Checking cmd 'pubkey' return code");
my $expected = slurp("$fixtures_dir/public-key.asc");
my @got = split(/\n/, $result);
splice(@got, 1, 1) if ($got[1] eq 'Version: GnuPG v2');
my $clean_got = join("\n", @got) . "\n";
is($clean_got, $expected, "Checking exported pubkey");

###############################################################################
### keygen
my $pubkey = `$sign -P $tmpdir/P -g "rsa\@2048" 800 "$comment" $prj_user`;
is($?, 0, "Checking cmd 'keygen' return code");
spew("$tmpdir/p", $pubkey);
system("gpg -q --import $tmpdir/p");
is($?, 0, "Checking pubkey import return code");

###############################################################################
### keyextend
my $pubkey2 = `$sign -P $tmpdir/P -x 1000 $tmpdir/p`;
is($?, 0, "Checking cmd 'keyextend' return code");
spew("$tmpdir/p2", $pubkey2);
system("gpg -q --import $tmpdir/p2");
is($?, 0, "Checking pubkey import return code");

###############################################################################
### keyid
$result = `$sign -k`;
is($?, 0, "Checking keyid return code");

###############################################################################
### privkeyid
$result = `$sign -P $tmpdir/P -k`;
is($?, 0, "Checking privkeyid return code");

###############################################################################
### certgen
my $cert = `$sign -P $tmpdir/P -C $tmpdir/p`;
is($?, 0, "Checking cmd 'certgen' return code");
my $end_cert = qr/-----END CERTIFICATE-----$/;
like($cert, $end_cert, "Checking for end of certificate");
spew("$tmpdir/c", $cert);
$result = `openssl verify -check_ss_sig -CAfile $tmpdir/c $tmpdir/c`;
is($?, 0, "Checking openssl verify return code");
$result = `openssl x509 -in $tmpdir/c -noout -pubkey`;
is($?, 0, "Checking openssl x509 return code");
spew("$tmpdir/cp", $result);

###############################################################################
### detached sign
spew("$tmpdir/sign", $payload);
$result = `$sign -d $tmpdir/sign`;
is($?, 0, "Checking detached sign return code");
my $verify_sign = `gpg --verify $tmpdir/sign.asc 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking detached sign signature");
unlink("$tmpdir/sign.asc");

###############################################################################
### detached privsign
spew("$tmpdir/privsign", $payload);
$result = `$sign -P $tmpdir/P -d $tmpdir/privsign`;
is($?, 0, "Checking detached privsign return code");
$result= `gpg --verify $tmpdir/privsign.asc 2>&1`;
like($result, qr/Good signature from/, "Checking detached privsign");
unlink("$tmpdir/privsign.asc");

###############################################################################
### detached raw sign
spew("$tmpdir/sign", $payload);
$result = `$sign -D $tmpdir/sign`;
is($?, 0, "Checking detached raw sign return code");
$result = `gpg --verify $tmpdir/sign.sig 2>&1`;
like($result, qr/Good signature from/, "Checking detached raw sign signature");
unlink("$tmpdir/sign.sig");

###############################################################################
### detached privsign
spew("$tmpdir/privsign", $payload);
$result = `$sign -P $tmpdir/P -D $tmpdir/privsign`;
is($?, 0, "Checking detached privsign return code");
$result = `gpg --verify $tmpdir/privsign.sig 2>&1`;
like($result, qr/Good signature from/, "Checking detached privsign signature");
unlink("$tmpdir/privsign.sig");

###############################################################################
### clear sign
spew("$tmpdir/sign", $payload);
$result = `$sign -c $tmpdir/sign`;
is($?, 0, "Checking clear sign return code");
$result = `gpg --verify $tmpdir/sign 2>&1`;
like($result, qr/Good signature from/, "Checking clear sign signature");
unlink("$tmpdir/sign");

###############################################################################
### clear privsign
spew("$tmpdir/privsign", $payload);
$result = `$sign -P $tmpdir/P -c $tmpdir/privsign`;
is($?, 0, "Checking clear privsign return code");
$result = `gpg --verify $tmpdir/privsign 2>&1`;
like($result, qr/Good signature from/, "Checking clear privsign signature");
unlink("$tmpdir/privsign");

###############################################################################
### openssl privsign
spew("$tmpdir/privsign", $payload);
$result = `$sign -P $tmpdir/P -h sha256 -O $tmpdir/privsign`;
is($?, 0, "Checking openssl privsign return code");
$result = `openssl dgst -verify $tmpdir/cp -signature $tmpdir/privsign.sig $tmpdir/privsign`;
like($result, qr/Verified OK/, "Checking openssl privsign signature");

###############################################################################
### rpm sign
$result = `rpm --dbpath $tmpdir --initdb`;
$result = `rpm --dbpath $tmpdir --import $fixtures_dir/public-key.asc`;
spew("$tmpdir/empty.rpm", slurp("$fixtures_dir/empty.rpm"));
$result = `$sign -h sha256 -r $tmpdir/empty.rpm`;
is($?, 0, "Checking rpm sign return code");
$result = `rpm --dbpath $tmpdir --checksig -v $tmpdir/empty.rpm`;
like($result, qr/^\s*Header V3 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm header signature");
like($result, qr/^\s*V3 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm header+payload signature");

###############################################################################
### rpm v4 sign
$result = `rpm --dbpath $tmpdir --initdb`;
$result = `rpm --dbpath $tmpdir --import $fixtures_dir/public-key.asc`;
spew("$tmpdir/empty.rpm", slurp("$fixtures_dir/empty.rpm"));
$result = `$sign -h sha256 -4 -r $tmpdir/empty.rpm`;
is($?, 0, "Checking rpm v4 sign return code");
$result = `rpm --dbpath $tmpdir --checksig -v $tmpdir/empty.rpm`;
like($result, qr/^\s*Header V4 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm v4 header signature");
like($result, qr/^\s*V4 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm v4 header+payload signature");

###############################################################################
### rpm priv sign
$result = `rpm --dbpath $tmpdir --import $tmpdir/p`;
spew("$tmpdir/empty.rpm", slurp("$fixtures_dir/empty.rpm"));
$result = `$sign -P $tmpdir/P -h sha256 -r $tmpdir/empty.rpm`;
is($?, 0, "Checking rpm privsign return code");
$result = `rpm --dbpath $tmpdir --checksig -v $tmpdir/empty.rpm`;
like($result, qr/^\s*Header V3 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm header signature");
like($result, qr/^\s*V3 RSA\/SHA256 Signature, key ID [0-9a-f]*: OK/m, "Checking rpm header+payload signature");

###############################################################################
### cleanup
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

