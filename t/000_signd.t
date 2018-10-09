#!/usr/bin/perl

use strict;
use warnings;
use bytes;
use Test::More tests => 12;
use File::Temp qw/tempdir/;
use File::Path qw/remove_tree/;
use Digest::SHA;


###############################################################################
### if ($cmd eq 'ping') {
my $ping_result = `GNUPGHOME=t/etc/gnupg ./signd -t ping "defaultkey\@localobs"`;
is($?, 0, "Checking cmd 'ping' return code");

my @keys = decode_reply($ping_result);

###############################################################################
### if ($cmd eq 'pubkey') {
my $pubkey_result = `GNUPGHOME=t/etc/gnupg ./signd -t pubkey "defaultkey\@localobs"`;
is($?, 0, "Checking cmd 'pubkey' return code");
my @out = decode_reply($pubkey_result);
my $expected = <<'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFu69OoBCAC56ghE41rcnBweNXeAWjwznaglBe3jTKdJiD9iJLQhRvvGY9OC
mPw2JnLIzqhITFBhF0YD1w0CMXphfTXtPJRuoC65rDQSB5zCBZjAYg8m9+wzMHuU
HQ7vIcjFqB444NoV8FBY6rRlGEZ+MaM4y4eidT62VKBtKMwvEWXFNLXNM5oZVmv7
ResbgLUyhNSTQVZyP2kyudPaZDJ4NASnGd9SA9IudiOVLU0HemwJgKf2DmKYLMBe
b70wfxUaM42I4qmqDJCK5hCZng2wY1XBgaWnF8+OeHLc+WLYFQNalFT8ctMHmuDG
5Z5L6jxXyW1DUBtM4tF7X77KXZiXEAwf8CN/ABEBAAG0OnByaXZhdGUgT0JTIChr
ZXkgd2l0aG91dCBwYXNzcGhyYXNlKSA8ZGVmYXVsdGtleUBsb2NhbG9icz6JATkE
EwECACMFAlu69OoCGy8HCwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAAKCRB1gfIr
5AqaL0hVB/0VXLIX69bGs9xXK13gIp8y0DmugJfj9KnIEdhhXpjkkKbGIriaG912
bSe6b7vVexnM9x2H1I6HdazMFtQLtYB3gw7cKVo+zjHpL+2KbkieFf0+xfM3uMG4
C8flAhEuFtAw3DO1qrmH2PoR39QTutUhG0vNyxU/mUudabm3C7w9hzRSkT8y02GF
lXFO7ecTDFfZyiNWa0vHfmq8SEmnlPzl2JRpRy0LO3XoVq9KFOffAWXDf3O8TGME
uaFpK899yfw7tg1jiv9PHXtDmZ2Sh2SrcaYUymPFFvlAqBW3yvyx1vxu/Omair0L
SMcaFYDkQDJT0s2wUckMRMdCUVLxaaT+uQINBFu69OoQCACh+9dS6eYWKRUjga+W
NBwSDxpinvQ4/EO/0nlwbx+fEcjIY9lcdzTP0Bwq4XUXnpK0TAjzA11AmFldlxJx
9bBtosZjZKH748mOw1+CpbLFhcbkQmgzh5pav1JBt5bSMwXNi/MXMMi+9i+0G7DV
Mc4Cn1a8w4SX8twR64dT24AbM7FLNOra7FqwcGZs65dXu19ECuRrqxRbg9rA27Pq
odfw9St2b0Ro69ppHdUVkywzcuaiikBUBiJ9P9a89TToPBRJ0Ec8iPB1aPPlo8Id
oR8fMMFb+4SSE+I7PhEkxo3ZqoQ3g5W30i0QPICQb8LIXccTOLiqnjurkp5E4Y35
s9MfAAMHCACAfKyeri3DyapJfv0SqVfgfv808SE6VfOj9gB4vOu6KcV7/xXhkAg5
zLZaaxGYGd27pTQwPFVmfUaxEEnjBmRRYWYLuTahgLGF8d1QPhqDvR4KwXfSkfhz
JtQhXFXbIZO9VEfedlaWfoAF1WnLbekrbksqANx/a/+0HiprEqdQAg/krrGsjySZ
eEJdjrWk9LO+2V8RkFD04LM+Z19EYkYQ+40+JMmfHSv+oVhKoB6fKcaxhvC2FH61
cb5ptducE3O0NtWu+U7kl2fdSAwFg0rZsHBHVybx7ibxNgLhoNDvvkWjRcNsSLPW
ZDNr8MaUw2D6+ajybyTCrgeKFiVsfrNXiQEfBBgBAgAJBQJbuvTqAhsMAAoJEHWB
8ivkCpov+vcIAJnxuuBgyUI9yRnuGl8gB+fFU42VSmOgYU8i8+ZEblgYylrE7UvP
AB+4Zib4tB4Ug+9MKGKDOXpQRoVvDAvwSiA378kB3iGGZAI1n2KzUapStTFm0mel
u/kN6M76OtIzjsBCZQCufx+QsGH5OQQ5o3ggzo39edqebRQyTDuArqG2VDrodFbX
JpYBW/4aNFlGVfum5F2mUE8UpKNNid/rcnUel9c5L22mIutvL+5IkkZxNix86guN
p7ito2MHkjMKceXfQhzgJ5Dk1x2Ep3JYuFjMl+rqjgeeUHjxwEm7ah5QRmAOjEDq
foSe9DQQ9z21ko8EDRlnZsOtZlsRR1DNSEU=
=7/lu
-----END PGP PUBLIC KEY BLOCK-----
EOF
;
my @got = split(/\n/, $out[0]);
splice(@got, 1, 1) if ($got[1] eq 'Version: GnuPG v2');
my $clean_got = join("\n", @got) . "\n";
is($clean_got, $expected, "Checking exported pubkey");

###############################################################################
### if ($cmd eq 'keygen') {
my $result = `GNUPGHOME=t/etc/gnupg ./signd -t keygen "defaultkey\@localobs" "rsa\@2048" 800 "just for testing" "signd\@localhost"`;
is($?, 0, "Checking cmd 'keygen' return code");
@keys = decode_reply($result);

my $privkey_packed = pack("H*", $keys[1]);
my $tmpdir = "t/tmp";

( -d $tmpdir ) || mkdir($tmpdir, 0700);

my $tmpprivkey_encrypted = "$tmpdir/privkey_encrypted";
spew($tmpprivkey_encrypted, $privkey_packed);

my $privkey_decrypted = `GNUPGHOME=t/etc/gnupg gpg --batch --decrypt  $tmpprivkey_encrypted 2>/dev/null`;
is($?, 0 , "Checking if decryption was successful");
my $tmpgnupghome = tempdir("XXXXXXX", DIR => $tmpdir);

my $tmpprivkey_decrypted = "$tmpdir/privkey_decrypted";
spew($tmpprivkey_decrypted, $privkey_decrypted);

$ENV{GNUPGHOME} = $tmpgnupghome;

my $importresult = `gpg --batch --import $tmpprivkey_decrypted 2>&1`;
is($?, 0, "Checking import of decrypted privkey");

###############################################################################
### if ($cmd eq 'certgen') {
my $cmd = "GNUPGHOME=t/etc/gnupg ./signd -t certgen \"defaultkey\@localobs\" \"$keys[1]\" 800 \"just for testing\" \"signd\@localhost\"";
my $certgen_result = `$cmd`;
is($?, 0, "Checking cmd 'certgen' return code");
my @certs = decode_reply($certgen_result, 1);
like($certs[0], qr/-----END CERTIFICATE-----/, "Checking for end of certificate");


###############################################################################
### Common vars for sign and privsign
my $trailer = pack("CN", 0, time());
my $payload = "test";
my $arg = Digest::SHA::sha1_hex("$payload$trailer").'@'.unpack("H*", $trailer);

###############################################################################
### if ($cmd eq 'privsign') {
$cmd = "GNUPGHOME=t/etc/gnupg ./signd -t privsign \"defaultkey\@localobs\" \"$keys[1]\" $arg";
my $privsign_result = `$cmd`;

is($?, 0, "Checking cmd 'privsign' return code");
my @privsign = decode_reply($privsign_result);
spew("$tmpdir/privsign", $payload);
spew("$tmpdir/privsign.sig", $privsign[0]);
my $verify_privsign = `gpg --verify $tmpdir/privsign.sig 2>&1`;
like(
  $verify_privsign,
  qr/Good signature from/,
  "Checking cmd 'privsign' for 'Good signature from'"
);

###############################################################################
### if ($cmd eq 'sign') {
my $sign_result = `GNUPGHOME=t/etc/gnupg ./signd -t sign "defaultkey\@localobs" $arg`;
is($?, 0, "Checking cmd 'sign' return code");
my @sign = decode_reply($sign_result);
spew("$tmpdir/sign", $payload);
spew("$tmpdir/sign.sig", $sign[0]);
my $verify_sign = `GNUPGHOME=t/etc/gnupg gpg --verify $tmpdir/sign.sig 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking for 'Good signature from'");

###############################################################################
### cleanup
remove_tree($tmpdir);

exit 0;

sub spew {
  my ($fn, $content) = @_;
  open(FH, '>',  $fn) || die "Could not open'$fn': $!\n";
  print FH $content;
  close FH;
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
