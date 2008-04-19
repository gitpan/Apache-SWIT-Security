use strict;
use warnings FATAL => 'all';

use Test::More tests => 54;
use File::Temp qw(tempdir);
use File::Slurp;
use Carp;
use YAML;
use Apache::SWIT::Maker::Config;

BEGIN { # $SIG{__DIE__} = sub { diag(Carp::longmess(@_)); };
	use_ok('T::Apache::SWIT::Security::Role::Container');
	use_ok('Apache::SWIT::Security::Maker');
	use_ok('Apache::SWIT::Security::Role::Container');
	use_ok('Apache::SWIT::Security::Role::Loader'); 
	use_ok('Apache::SWIT::Security::Role::Manager'); 
}

unlike(read_file('blib/conf/httpd.conf'), qr/SWITSecurityPermissions/);
is(ADMIN_ROLE, 1);
is(USER_ROLE, 2);

my $man = Apache::SWIT::Security::Role::Manager->new({
	"some/url/r" => {
		perms => [ Apache::SWIT::Security::Role::Manager::ALL ],
	}
});
ok($man);
is($man->access_control("some/strange/url"), undef);

my $ac = $man->access_control("some/url/r");
ok($ac);

# if we want to allow all with no user check, just don't put access control
is($ac->check_user, undef);

$ac->{_perms} = [ -1*Apache::SWIT::Security::Role::Manager::ALL ];
is($ac->check_user, undef);
$ac->{_perms} = [ 12 ];
is($ac->check_user, undef);

my @roles = (12);

package User;
sub role_ids { return @roles };

package main;
is($ac->check_user('User'), 1);
@roles = (13);
is($ac->check_user('User'), undef);

$ac->{_perms} = [ 12, 13 ];
is($ac->check_user('User'), 1);
$ac->{_perms} = [ -13, 13 ];
is($ac->check_user('User'), undef);

my $sec_yaml_str = <<ENDS;
roles:
  1: admin
  2: user
pages: {}
ENDS
my $loader = Apache::SWIT::Security::Role::Loader->new;
my $tree = Load($sec_yaml_str);
bless($tree, 'Apache::SWIT::Maker::Config');
$loader->load_role_container($tree->{roles});
$loader->load($tree);

is($loader->roles_container->find_role_by_id(2)->name, 'user');
is($loader->roles_container->find_role_by_id(1)->id, 1);
eval { $loader->roles_container->find_role_by_id(3); };
like($@, qr/Unable to find/);
is($loader->roles_container->find_role_by_name('admin')->id, 1);

is_deeply([ $loader->roles_container->roles_list ], [ 
		[ 1, 'admin' ], [ 2, 'user' ] ]);
isa_ok($loader->url_manager, 'Apache::SWIT::Security::Role::Manager');

my $sec_yaml_str2 = <<ENDS;
roles:
  1: admin
  2: user
  3: manager
root_location: /root
pages:
  some/url:
    entry_points:
      r:
        permissions: [ +all ]
      u:
        permissions: [ -user, +all ]
  other/url:
    entry_points:
      r:
        permissions: [ +manager ]
  ok/aga:
    entry_points:
      r:
        permissions: []
  han/page.txt:
    handler: momo
    permissions: [ +manager ]
  old:
    entry_points:
      one: {}
rule_permissions:
  # not going to work because of entry point permissions
  - 
    - '.*some.*'
    - '-all'
  - [ '/root/foo/bah' ]
  - [ '.*boo.*', '+manager' ]
  - [ '.*/ok/.*', '+all' ]
  - [ '/root/foo/.*', '+all' ]
capabilities:
  moo_cap: [ +manager ]
  user_can: [ +user ]
ENDS
my $loader2 = Apache::SWIT::Security::Role::Loader->new;
$tree = Load($sec_yaml_str2);
bless($tree, 'Apache::SWIT::Maker::Config');
$loader2->load_role_container($tree->{roles});
$loader2->load($tree);
$man = $loader2->url_manager;

$ac = $man->access_control("/root/some/url/r");
ok($ac);
is($ac->check_user('User'), 1);

# only absolute urls going to work. For relative ones see URI->abs in Session
is($man->access_control("other/url/r"), undef);

is($man->access_control("/root/foo/bah"), undef);
is($man->access_control("ok/aga/r"), undef);

$ac = $man->access_control("/root/some/url/u");
ok($ac);
is($ac->check_user('User'), 1);

$ac = $man->access_control("/root/other/url/r");
ok($ac);
is($ac->check_user('User'), undef);

@roles = (2, 3);
$ac = $man->access_control("/root/other/url/r");
is($ac->check_user('User'), 1);

$ac = $man->access_control("/root/some/url/u");
is($ac->check_user('User'), undef);

$ac = $man->access_control("/root/han/page.txt");
isnt($ac, undef);

$ac = $man->access_control('moo_cap');
is($ac, undef);

$ac = $man->capability_control('moo_cap');
isnt($ac, undef);
is($ac->check_user('User'), 1);

eval { $man->capability_control('foo_cap'); };
like($@, qr/capability foo_cap/);

$ac = $man->access_control("/strange/boo");
isnt($ac, undef);
is($ac->check_user('User'), 1);

$ac = $man->access_control("/some/boo"); # deny for all works here
isnt($ac, undef);
is($ac->check_user('User'), undef);

$ac = $man->access_control("/ok/ggg");
isnt($ac, undef);
# we have access control but no user: should not allow +all
is($ac->check_user, undef);

$ac = $man->access_control("/root/old/one");
is($ac, undef);

$ac = $man->access_control("/root/foo/a.txt");
isnt($ac, undef);

my $td = tempdir("/tmp/100_manager_t_XXXXXX", CLEANUP => 1);
chdir $td;

mkdir 'conf';
mkdir 'blib';
mkdir 'blib/conf';
write_file('conf/swit.yaml', $sec_yaml_str2);

$tree = Apache::SWIT::Maker::Config->instance;
$tree->{env_vars}->{AS_SECURITY_MANAGER} = 'R::C::Role::Manager';
$tree->{env_vars}->{AS_SECURITY_CONTAINER} = 'R::C::Role::Container';
$tree->{env_vars}->{AS_SECURITY_USER_CLASS}
	= 'Apache::SWIT::Security::DB::User';
Apache::SWIT::Security::Maker->new->write_sec_modules;
ok(require("blib/lib/R/C/Role/Container.pm"));
ok(require("blib/lib/R/C/Role/Manager.pm"));

my $rcc = R::C::Role::Container->create;
is_deeply($rcc, $loader2->roles_container);
isa_ok($rcc, 'R::C::Role::Container');
is($rcc->find_role_by_id(1)->name, 'admin');

my $mcc = R::C::Role::Manager->create;
is_deeply($mcc, $loader2->url_manager);

chdir('/');

