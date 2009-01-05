use strict;
use warnings FATAL => 'all';

package T::Basic;
use Apache::SWIT::Security qw(Sealed_Params);
 
sub handler {
	my $r = shift;
	my ($a, $c) = Sealed_Params(Apache2::Request->new($r), 'a', 'c');
	$a ||= "NONE";
	$c ||= "NONE";
	$r->content_type("text/plain");
	print "hhhh\n$INC[0]\na=$a\nc=$c\n";
	return Apache2::Const::OK();
}

1;
