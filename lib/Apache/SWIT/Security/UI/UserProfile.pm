use strict;
use warnings FATAL => 'all';

package Apache::SWIT::Security::UI::UserProfile;
use base qw(Apache::SWIT::HTPage);
use Digest::MD5 qw(md5_hex);
use Apache::SWIT::Security qw(Sealed_Params);

sub swit_startup {
	my $rc = shift()->ht_make_root_class('HTML::Tested::ClassDBI');
	$rc->ht_add_widget(::HTV."::EditBox", 'name', cdbi_bind => '');
	$rc->ht_add_widget(::HTV."::Marked", 'error');
	$rc->ht_add_widget(::HTV."::Hidden", 'user_id', cdbi_bind => 'Primary');
	$rc->ht_add_widget(::HTV."::PasswordBox", $_)
		for qw(new_password_confirm new_password old_password);
	$rc->ht_add_widget(::HTV."::Form", form => default_value => 'u');
	$rc->bind_to_class_dbi($ENV{AS_SECURITY_USER_CLASS});
}

sub ht_swit_render {
	my ($class, $r, $root) = @_;
	$root->cdbi_load;
	return $root;
}

sub ht_swit_update_die {
	my ($class, $err, $r, $tested) = @_;
	my $em = ($err =~ /WRONG/) ? "Wrong password"
			: ($err =~ /MISMA/) ? 'Passwords do not match' : undef;
	$class->SUPER::ht_swit_update_die(@_) unless $em;
	return $tested->ht_make_query_string("r", "user_id") . "&error=$em";
}

sub ht_swit_update {
	my ($class, $r, $root) = @_;
	my $u = $root->cdbi_retrieve;
	die "WRONG" if $u->password ne md5_hex($root->old_password);
	die "MISMA" if $root->new_password ne $root->new_password_confirm;
	$u->password(md5_hex($root->new_password));
	$root->cdbi_update;
	return $root->ht_make_query_string("r", "user_id");
}

sub check_profile_user {
	my ($class, $r) = @_;
	my $s = $r->pnotes('SWITSession') or return;
	my $u = $s->get_user or return;
	my ($ruid) = Sealed_Params($r, 'user_id');
	return $ruid ? ($ruid eq $u->id) : undef;
}

1;
