use strict;
use warnings FATAL => 'all';

package Apache::SWIT::Security::UI::UserForm;
use base qw(Apache::SWIT::HTPage);
use Digest::MD5 qw(md5_hex);

sub swit_startup {
	my $rc = shift()->ht_make_root_class('HTML::Tested::ClassDBI');
	$rc->ht_add_widget(::HTV."::EditBox", 'username', cdbi_bind => 'name');
	$rc->ht_add_widget(::HTV."::PasswordBox", 'password', cdbi_bind => '');
	$rc->ht_add_widget(::HTV."::PasswordBox", 'password2');
	$rc->ht_add_widget(::HTV, 'password_mismatch');
	$rc->bind_to_class_dbi(
		$ENV{AS_SECURITY_USER_CLASS}, { PrimaryKey => [] });
}

sub ht_swit_validate {
	my ($class, $r, $root, $args) = @_;
	if ($root->password ne $root->password2) {
		delete $args->{$_} for qw(password password2);
		return "r?password_mismatch=1";
	}
	return shift()->SUPER::ht_swit_validate(@_);
}

sub ht_swit_render {
	my ($class, $r, $root) = @_;
	return $root;
}

sub ht_swit_update {
	my ($class, $r, $root) = @_;
	$root->password(md5_hex($root->password));
	$root->cdbi_create_or_update;
	return "../userlist/r";
}

1;