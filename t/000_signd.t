#!/usr/bin/perl

use strict;
use warnings;
use bytes;
use Test::More tests => 14;
use File::Temp qw/tempdir/;
use File::Path qw/remove_tree make_path/;
use Digest::SHA;
use FindBin;

my $user     = 'defaultkey@localobs';
my $prj_user = 'signd@localhost';
my $comment  = "just for testing";
my $var_dir  = "$FindBin::Bin/tmp/var";

###############################################################################
### Prepare tests
remove_tree("$FindBin::Bin/tmp/");

make_path($var_dir);
$ENV{SIGND_VAR} = $var_dir;
$ENV{LANG} = 'C';
my $fixtures_dir = "$FindBin::Bin/fixtures";
my $gnupghome=$ENV{GNUPGHOME};
$ENV{GNUPGHOME} = "$FindBin::Bin/tmp/gnupg";
make_path($ENV{GNUPGHOME});
chmod 0700, $ENV{GNUPGHOME};
`gpg -q --import $fixtures_dir/secret-key.asc `;

my $sign_conf = "$FindBin::Bin/tmp/sign.conf";
$ENV{SIGN_CONF} = $sign_conf;
spew("$sign_conf","user: $user
server: 127.0.0.1
tmpdir: $var_dir
allowuser: obsrun
allow: 127.0.0.1
phrases: $FindBin::Bin/tmp/gnupg/phrases
");

make_path("$FindBin::Bin/tmp/gnupg/phrases");

# simulate touch
spew("$FindBin::Bin/tmp/gnupg/phrases/$user", '');

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
my $result = `./signd -t keygen $user "rsa\@2048" 800 "$comment" $prj_user`;
is($?, 0, "Checking cmd 'keygen' return code");
@keys = decode_reply($result);

my $privkey_packed = pack("H*", $keys[1]);
my $tmpdir = "t/tmp";

( -d $tmpdir ) || mkdir($tmpdir, 0700);

my $tmppriv_encrypted = "$tmpdir/privkey_encrypted";
spew($tmppriv_encrypted, $privkey_packed);

my $priv_decrypted = `gpg --batch --decrypt  $tmppriv_encrypted 2>/dev/null`;
is($?, 0 , "Checking if decryption was successful");
my $tmpgnupghome = tempdir("XXXXXXX", DIR => $tmpdir);

my $tmppriv_decrypted = "$tmpdir/privkey_decrypted";
$priv_decrypted .= pack('CC', 13 + 192, 8).'privsign';
spew($tmppriv_decrypted, $priv_decrypted);

$ENV{GNUPGHOME} = $tmpgnupghome;

my $importresult = `gpg --batch --allow-non-selfsigned-uid --import $tmppriv_decrypted 2>&1`;
is($?, 0, "Checking import of decrypted privkey");

$ENV{GNUPGHOME} = "$FindBin::Bin/tmp/gnupg";
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
$ENV{GNUPGHOME} = "$FindBin::Bin/tmp/gnupg";

my $expired_key="85020e0384a9757a0207a14b1007ff44feac890e42cc1699fde7c37073831e87a409b7c75bf74f20bc9cea3a86194f9bcf34473adf5d5022c35787a7633e0cd4b8c104636c17728a273cd64004f549b2164fdb569275200baa9328bb25781a955d4b9cedc3195c64a5958a58881d031d212801630c694d4c6665c57fe6085949aeb69552fdc92a8b5e9eeae03eec833ffb0fc91afce812527b6b426bd536624fc9c4196afdf4e67937397f6bdd3022571ad3a1749933efd84a31d3a1578fd9e28ae5fe1c6b8b7fea68e2975211f32ee7783ce1e0916d5f1ea1d70f64fbb96e789b43b3cc5f248da2299ddf9a8766a646958fb91dab508c7b2b82881d04ded3205c4359c65d65dbe0695f841e82956b0800804d19987999b85de016f0a4f13590bd8da0ca4846f287e8dcf6fc1be10a54d37cc000b616467052b26d17357562f38da42528807dffac56c9b7866bc071e5407cfa8a2e3bb7f1c83acb7875fe17e2df03cfa26e6e7afa6f92bed2d23366997a489d7a7e5c64a8b96bc6b1637e3dc7c77eaf673fc8200ee0b933bfb92303283c63d1016e42fae49b0f051edb1d77096ab9e474120fde67ad2e849a322b44e94615180f8f3c08ea1697eb9f67f5e5152e333250bf4904afe0640fe56e863130b4553e0e6191f2c26cc65ab55e8a5e9ac16f0dc5bbfa60dadd43ce0ca3880c6d99c2edcc99e9a04a70235c026a889a1248c008f2e42d77787adc627802fed8bc29d2eb01869cc3ee119ca13c77987b308df9f58814d2dcf4d200de21a5da919f018a05330ebef1ba7b35d964b35e872f7eeaecfa858c410f3674cbc37bf592102b19aa22fefcbe238b66da7bfe65bd145c5b288814f18d83c9b973726a89301543ded73924120f63ee046e2f6c6a4dfbbcdf3a488866af5f3676600af61add712ba5255c2bacce6ff42dcf38a287bf598d5877e1bc70e0e4091525626d13c00ce35d91116dcc4b633fbeeaea55a55f6b49f4d035871d7be8bb9c6ad4cbd648f43bd2812945fe08f2da27a78d0660b69a0139fa8d05de37ce37cefd9ef574cf49fc7a8bf9c4d45af58c6a0a4c532fb4761d1b16238405858c06385606b8dbe62a8e9175d92095fca624a2e2c9ae159042865446856c0270c700f2b2ef931e8af751c0ec4c13f875e94d4eb113cd048c9f9748536901a939343542fc4d63ae2170aaa21861ed168352a022fef81d93a4d7069d134239cfd78d33339504a772c44310d7fab3fa991af6c034bf6b0d3362131fedd338dc32449bb9ed5b5f84fbea7b8ea7d4d45257b83835d97977c2bf90c64d852794eaa793d0ed886e0bcd483184fe7094b550f5b295b427449dfa3c56e86913edfa4bdc1e1e41b357ceaf626979ecf7942c0acd2ead69e96caf563303d3f14b5e2ac0ec5379c0fc5974ea3fda1792a5d9020ac8d790acaec28bc1062064c0fcde6df8d4f1ca8a9f933742596ab152a8651bece1c9f8d4a839f1c44f4f1cca379fbbf78c9214f788e161f63682089352e9cacde851cbe55e2b064bda5e14fe69fb482369e85982e1d1eb862f1ffc1a51f14ae25b721a4466edad6db63b39f301bd23c5c9b47f12302b749ebfce0ee72518dab4ef9ed68afe2a186e1ac221147219469390f0b3e37c19ca38724f636e797abdbe1e811f8eb46c6ae65c1e7dc4f0a7a409c36ecf8a042c4a74f1d9fdf62964524cc1542c7fdb726c8ed319106f874d6cd5029453e025c1ce2ff332884080d84cc87a07aadd7a17097f763fdaede00338f873bf4d8d0a97a50622c02fa5dc30ab964a67ea578a87d51a2170611a3a6a0694e56898767089ebdef1f1613e3647bc7b15734857455c5efeecfb68f5af53e323ae8aaaec2b0847267d58f04c3b9f897944ffbc457dcaa3e73fc313a790f788c4f2b5db84113e600981c0db6ead15c97ba72aabb7fb9a38e639875bc80fdaad3dc86618277a515de47d4ae0449e8831c30538da29ac8d88773c93561ab61237d543e7ce5d362e16f1fcc3e1f9ba3b166b7790a303003b333efcfd879009a77ddb66a62f0c15c01e62ba7773e170ee9109b5e2e03f9a02443dc2d68f19977696e570528d5f5269d75e88f320bf37d3d2394e4b2b4a0b2b0eeff36d64249cfba90393cea12ba05b35c1f090ffcf1977b0b407eec1fc03715d99233c28290764cdfca494251c5aae5a382e2775a0b3595bfc7f39cb7f1557dcbf80d415a219598fdf10f34f253f60cdf19a664ebaecd3559df0c0622a64f8b7d7632187e25f939fe59e52175e7d20621e175d394b9102722c1d0417d748e24d8fe28f0fbb7beb46a4caad613a4147e9df5b61384a65ea03e4be04f2ef6bdc521d7339875a6ec2f23b3582ded8ede1835f04f24f96c9fd95c4582aba59111ad4a83cfc3d362f4d6cc719a2259fa040b14ab7e4953e002d4c6b122b2b45b2241b20911750f11438f25dafaa8d5a7e17ba910adc4ed4be9cc955c31735e361a4ffb5246fe50860954b4aa2219c667fd2147b0bda1164a34a26c21475aca5a525c6e2d3dd8728a06b8e336acd241c4c081d225a77001e3f3b5d006a1c8d574689e4d2f1799091c8531c6b4cb85c3a6de1b831f94521e03aeff2060f9ee995cb292bac535649e5a8e60c4e8c29d73abaaf9ef58d9c7b92345fa607efc5679ce44ce7dc209f3a4774282201f6e92fbf9384534b24ed2c8fd910a5baaa60ce4d4791994c9245169c11e0f6df3e448350a3d7b45b6b5dc42c4b197fcd668086b7805284a8dedb35a7081fd861163c2d9106c3ba63364e25073e544d376ea3e390bbf8295494706f8ce3af829f9af672bbe87ff1941982e45ca6176fb66ea3baeda315e8f61d9a088ea91348b68b9e7668df86b65a6e18425c83f8fea76f3f354096831614fe3b07b9636d96463435842ac34a2e41a2f703502e75fae92e68959ef782dfc0fc54e4c08cd6bca9f747bd1c683909fa9cbbe6ce49f201e33cadc3acd189dc54d2d5d5277095445ada367c8f9d1e520b7e8e7d167313f5ae211e8ebd5ee64e70b92c6bdaf2003271b36671b88e142084f70739b307107a260542d1750a39a7518444f50e972e438c305117d1f70470fe761480434110675571e47af9c976b264e30a51504d9e32a3e0b64580a7104eea6feba202d3364c00b86b773c7f3cdf40dcd01c5eb5fe66353b04456e57e4c63ffc857293a2bbc2fd14e0fe2726d12fc1cd19625f336112b1a84fe0cb2d8dc8ff2d62fb9a1922f1f4d4dac4413557ce305ca9dc6e92ca06995f68c23e105696ad916ccc454d916281664ecc8273d9a8a4c2a64010ab61ad3743e7c57a57b991ea1330745c6d54abbcfffb3fdeaf811d66858392d924fc12991e3535b6b07ecf5eea2296a7ac2593707145db108b6d169dcfd3133dc079d0c39691bb7884753bc10b803e049d3a1bc820aff6d019b04265ac31232660af4d2cdc78993121f5498021fc0bed37f9ca1154edd43488334bba641e73542ccec2673c90f436a2d767e4638b7be9349f8d99bdf2117d976b0c1839dd3e36a543d49b4bae33b3e4b2565f85a72e1c5873dac2722bb4b4bd1c7214e4edb8981147ad94320b9dfb992ac89a6613479e8532624bb584ba4e4919c146a4893e2be1ef00a8c2dfb024fa65e672f30a1bd0bee2e9d9ec4608ade91b7e2154f0463f0267fc6e81b6a726c7c0364bd0d1aba376812d62ed3a88ebbe63dcd759829e6fe13a132ee104a9f71286e7e75440662251ff6573e9ee774620a03ecef4822460aff68789532e3043e35e19eef5bcac6d4b129dfc4a638c404fbb90faa56345546c8b01435a150f44a32ccff667e804a7367aad43293e7b39c2a23d00e7334d4928f84d651fac397756fe9ed9c077b6f8fe5b9b51fbbeb337bd2a97a5c98ae7fec39a09401e84e44ae61b1ab46173db0f2bf432fd4dfcbe4a4b5a924d7879675b6ffb9e0138ec4266f8a1088d75bb7431b306a1fc44158c9c81701a443bac6cec16ef7a4de8cd96acce163ae8f070091afb72fb5f98d1f64e5fdf7115a728677cc65d35d75e76c62e408154b7a28030052c7ff31d96b3f387b1c445ae16eec90ac8170b33cfdbe890301f15b71d436bd1ab52a6a1cb96b665a142d3ba8b30eb542038b9f94ae3657d499b865e79923b44ff851b57ed2b58cb5c2bb89fb6675b6917fd9976469347185d790c68cc05ef31b559f3e21b4189351d2c554280e50d67877ace59b0a2254d9d3a8452be9792ca44f6c1ffa6f6412af480828b08db27c6ae88769dfccc5d33d9e24c11ee07de32e2e92150a1d5f1e5d6775cb71550bfa0b7e78597db69db34a3acb85e26ff6c5572ccb771491c76fcfca543b5ca767e6920bd95140bc04a043a34a29b1e532efce797474190bd976eeb1cbb083cb320d3f3f9a08971f52b82bff25fc1dacc66f8259ebc93b8754a1bf6081bedef175c51e41a1b0d82015118f388fd0438aa232c66e8d8dc6e";


$cmd = "./signd -t privsign $user $expired_key $arg";
#print "$cmd\n";
$privsign_result = `$cmd`;

is($?, 0, "Checking cmd 'privsign' return code (expired key)") || print $privsign_result;
@privsign = decode_reply($privsign_result);
spew("$tmpdir/privsign", $payload);
spew("$tmpdir/privsign.sig", $privsign[0]);
$ENV{GNUPGHOME} = $tmpgnupghome;
`gpg --import $FindBin::Bin/fixtures/secret-key-expired.asc 2>&1`;
$verify_privsign = `gpg --verify $tmpdir/privsign.sig 2>&1`;
like(
  $verify_privsign,
  qr/Good signature from/,
  "Checking cmd 'privsign' for 'Good signature' (expired key)"
);

$ENV{GNUPGHOME} = "$FindBin::Bin/tmp/gnupg";



###############################################################################
### if ($cmd eq 'sign') {
my $sign_result = `./signd -t sign $user $arg`;
is($?, 0, "Checking cmd 'sign' return code");
my @sign = decode_reply($sign_result);
spew("$tmpdir/sign", $payload);
spew("$tmpdir/sign.sig", $sign[0]);
my $verify_sign = `gpg --verify $tmpdir/sign.sig 2>&1`;
like($verify_sign, qr/Good signature from/, "Checking for 'Good signature'");

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
