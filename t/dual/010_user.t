use strict;
use warnings FATAL => 'all';

use Test::More tests => 24;
use Apache::SWIT::Security::Test qw(Is_URL_Secure);

BEGIN { use_ok('T::Test'); }

my $t = T::Test->new;
$t->reset_db;

$t->ok_ht_login_r(make_url => 1, ht => { username => '', password => '' });
$t->ht_login_u(ht => { username => 'admin', password => 'password' });
$t->ok_ht_result_r(ht => { username => 'admin' });

$t->ok_follow_link(text => 'Add more users');
$t->ok_ht_userform_r(ht => { username => '', password => '', });
$t->ht_userform_u(ht => { username => 'user', password => 'p'
		, password2 => 'p' });

$t->ok_ht_login_r(make_url => 1, ht => { username => '', password => '' });
$t->ht_login_u(ht => { username => 'user', password => 'p' });
$t->ok_ht_result_r(ht => { username => 'user' });

$t->with_or_without_mech_do(8, sub {
	is($t->mech->follow_link(text => 'Add more users'), undef);
	is($t->mech->follow_link(text => 'User Role List'), undef);
	ok(Is_URL_Secure($t, $_)) for map { ("$_/r", "$_/u") }
		qw(userform userlist userrolelist);
});

$t->ok_ht_login_r(make_url => 1, ht => { username => '', password => '' });
$t->ht_login_u(ht => { username => 'admin', password => 'password' });
$t->ok_ht_result_r(ht => { username => 'admin' });

$t->ok_follow_link(text => 'User Role List');
$t->ok_ht_userrolelist_r(ht => { user_list => [
	{ HT_SEALED_ht_id => '1', name => 'admin', role_name => 'admin'
		, HT_SEALED_role_id => 1 }
	, { HT_SEALED_ht_id => '2', name => 'user', role_name => ''
		, HT_SEALED_role_id => '' }
] });

$t->ok_ht_result_r(make_url => 1, ht => { username => 'admin' });
$t->ok_follow_link(text => 'Logout');
$t->ok_ht_login_r(param => { logout => 'admin' }
		, ht => { username => '', password => '', logout => 'admin' });

$t->with_or_without_mech_do(2, sub {
	like($t->mech->content, qr/admin.*logged out/);
	$t->ht_userform_r(make_url => 1);
	is($t->mech->status, 403);
});
