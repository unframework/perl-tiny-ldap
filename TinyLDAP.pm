
=head1 NAME

TinyLDAP - very small and simple LDAPv1 implementation

=head1 DESCRIPTION

This module serves as a very small standalone replacement
for basic functionality of the Net::LDAP module.
It is implemented in pure Perl, so it can be used in minimal
Perl installations. The only dependency is the standard C<Socket>,
C<Errno> and C<Fcntl> modules (not C<IO::Socket>) for the basic
socket operation functions.

Currently, anonymous or simple authentication can be used.
Only searching is supported.

=over 4

=cut

# TODO: send an unbind when closing connection? look in RFC if it's ok to simply close conn

package TinyLDAP;
use strict; # spank me

my $_timeout = 5; # read timeout for socket operations

use Socket qw(SOL_SOCKET SO_ERROR PF_INET SOCK_STREAM inet_aton sockaddr_in); # just for definitions, should be fast
use Errno qw(EINPROGRESS); # just for definitions, should be fast
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK); # just for definitions, should be fast

# BEGIN { warn "compiling TinyLDAP\n"; }

# BERBoolean => 0x01;
# BERInteger => 0x02;
# BERString => 0x04;
# BEREnum => 0x0a;
# BERSequence => 0x30;

##  BER-encoding

# private
# BER-encodes a generic sequence of octets and puts the given type
# number in front
sub toBER($@)
{
    my $tag = shift;
    my $contents = join('', @_);
    my $len = length($contents);
    if($len < 128) { return pack('C2', $tag, $len) . $contents; }
    my $lenenc = pack('N', $len);
    $lenenc =~ s/^\x0+//s;
    pack('C2', $tag, 128 + length($lenenc)) . $lenenc . $contents;
}

# private
# encodes a full boolean value (tag included)
sub toBERBoolean($) { pack('C3', 0x01, 1, ( $_[0] ? 255 : 0 )); }

# private
# encodes a signed integer value (just the contents)
# note that we support only up to 32-bit values
sub int2ber($)
{
    my $int = $_[0];
    if($_[0] >= 2147483648 or $_[0] < -2147483648) { return ''; } # check for overflow
    if($int < 0) { $int += 4294967296; } # binary complement
    $int = pack('N', $int);
    $int =~ s/^\x0+([\x0-\x7f])/$1/; # shorten the thing properly
    $int =~ s/^\xff+([\x80-\xff])/$1/;
    return $int;
}

##  BER-decoding

# private
# takes a variable-length big-endian sequence of bytes and converts it
# to corresponding integer value (useful for BER integers as well as BER lengths)
# we support up to 32-bit signed integers
# as a special case for large unsigned Counter32 values, we can accept 5-byte ints
# provided that the first byte is zeroes (unsigned 0x80000000 and larger need that first byte to show sign)
sub ber2int($)
{
    my $bin = $_[0];
    my $l = length($bin);
    if($l < 5) # regular case
    {
        # fill out the 4 bytes
        $bin = ($bin =~ /^[\x0-\x7f]/ ? "\x0" : "\xff") x (4 - $l) . $bin;
        $bin = unpack('N', $bin);
        return ($bin < 2147483648 ? $bin : $bin - 4294967296); # and now get the complement
    }
    if($l > 5 or $bin !~ /^\x0/) { return undef; }
    # counter32-like int
    return unpack('N', substr($bin, -4));
}


# private
# accepts a reference to a buffer; parses BER tokens from it
# (while removing parsed data from buffer); returns tag=>value results
my $binBuffer; # reused between calls (to save allocation)
my @resultsBuffer;
sub parseBERTokens($)
{
    my $data = $_[0]; # external buffer reference
    $#resultsBuffer = -1;
    my($dataLen, $length, $tagByte, $lenEnc, $lenEncLen);

    # do the parsin'
    while($dataLen = length($$data))
    {
        if($dataLen < 2) { last; } # incomplete buffer
        ($tagByte, $length) = unpack('CC', $$data);
        if($length >= 128)
        {
            $lenEncLen = $length - 128; # size of extended length field
            if($lenEncLen + 2 > $dataLen) { last; } # incomplete buffer

            $lenEnc = substr($$data, 2, $lenEncLen);
            $length = unpack('N', substr("\x0\x0\x0$lenEnc", -4)); # fill up to full 4 bytes

            if(2 + $lenEncLen + $length > $dataLen) { last; } # incomplete buffer
            $binBuffer = substr($$data, 0, $length + 2 + $lenEncLen, ''); # remove whole packet
            substr($binBuffer, 0, 2 + $lenEncLen, ''); # strip header
        }
        else # faster ops for tiny elements
        {
            if($length + 2 > $dataLen) { last; } # verify
            $binBuffer = substr($$data, 0, 2 + $length, '');
            substr($binBuffer, 0, 2, ''); # get rid of tag and length
        }

        push @resultsBuffer, $tagByte, $binBuffer;
    }

    # done!
    return @resultsBuffer;
}

=item new(host, bindDN, password)

Creates a new TinyLDAP object.

B<host> specifies either a single host or an array of hosts to connect to.
A host specification may end with a colon and an integer, indicating the port
to connect to (default is 389). If a list of hosts is supplied, each entry
is tried until a successful connection is made.

If B<bindDN> is specified, a DN+password bind is made (password taken from
the B<password> argument). Otherwise, an anonymous bind is attempted.

Returns a TinyLDAP object instance or C<undef> on connection or authentication
error.

Example:

    my $ldap = new TinyLDAP([ 'mainsrv.acmeinc.com', 'bkpsrv.acmeinc.com',
        'weirdsrv.acmeinc.com:8389' ], 'uid=joeuser,ou=people,o=acmeinc', 'pass123');

=back

=cut

# if second argument is true, sets non-blocking, blocking otherwise
sub setNonBlock($$)
{
    my($fh, $on) = @_;
    my $flags;
    fcntl($fh, F_GETFL, $flags);
    if($on) { $flags |= O_NONBLOCK; }
    else { $flags &= (~O_NONBLOCK); }
    fcntl($fh, F_SETFL, $flags);
}

sub new($$@)
{
    my($class, $hosts, $bindDN, $password) = @_;
    my $self = { };
    bless $self, $class;

    $self->{'nextMsgID'} = 10;

    # check params
    if(defined $bindDN) { defined $password or return undef; }
    if(not defined $bindDN) { $bindDN = ''; $password = ''; }

    # now try open socket
    my @ldapHosts = (ref($hosts) eq 'ARRAY' ? @$hosts : ( $hosts ));
    foreach(@ldapHosts)
    {
        my $port = 389;
        my $host = $_;
        if($host =~ /^(.+):(\d+)$/s) { $host = $1; $port = $2; }

        my $iaddr = inet_aton($host) or next;
        my $paddr = sockaddr_in($port, $iaddr);
        local *SOCK;
        socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or next;

        # non-blocking timed connect
        setNonBlock(*SOCK, 1); # unblock and wait for connect
        (not connect(SOCK, $paddr) and $! == EINPROGRESS) or next;
        my $wbits = '';
        vec($wbits, fileno(SOCK), 1) = 1;
        (select(undef, $wbits, undef, $_timeout) == 1) or next;
        (getsockopt(SOCK, SOL_SOCKET, SO_ERROR) !~ /[^\x0]/) or next;
        setNonBlock(*SOCK, 0); # set to blocking again

        $self->{'socket'} = *SOCK; # good to go
        last;
    }
    unless($self->{'socket'}) { return undef; }

    # now bind
    my $socket = $self->{'socket'};
    my $msgid = 1;

    my $request = toBER(0x30,
        toBER(0x02, int2ber($msgid)),
        toBER(0x60 | 0, # application[0]
            toBER(0x02, int2ber(3)), # ldap version 3
            toBER(0x04, $bindDN), # ldap bind DN
            toBER(0x80 | 0, $password) # ldap simple auth string
            )
        );
    send($socket, $request, 0) or return undef;

    # listen for response
    # we expect it all to fit within 1024 bytes so we don't bother
    # checking for incomplete buffer
    my($rbits, $data) = ('');
    vec($rbits, fileno($socket), 1) = 1;
    select($rbits, undef, undef, $_timeout) and
        recv($socket, $data, 1024, 0);

    # walk the parsed tree
    my($seqTag, $seq) = parseBERTokens(\$data);
    $seqTag == 0x30 or return undef;

    my($msgidTag, $msgid, $opTag, $op) = parseBERTokens(\$seq);
    ($msgidTag == 0x02 and ber2int($msgid) == 1) or return undef;

    $opTag == 0x61 or return undef;
    my($resultTag, $result) = parseBERTokens(\$op);
    ($resultTag == 0x0a and ber2int($result) == 0) or return undef;

    return $self;
}

=head1 METHODS

=over 4

=item simpleSearch(base, scope, condAttr, condValue, returnAttrs...)

Performs a simple search with a scope of 'sub', 'one' or 'base' and the condition
being that a value of B<condAttr> attribute exactly matches B<condValue>.

B<base> specifies the base DN under which to search.

B<returnAttrs> specify zero or more attributes of found entries
to return values for. If no attributes are specified, entire entries
are returned.

Returns a hash of form:

    entryDN1 => { attr1 => [ values... ], attr2 => [ values... ] ... },
    entryDN2 => { attr1 => [ values... ], attr2 => [ values... ] ... }
    ...

Keys in entry hashes (attribute names) are always lowercase.

Example:

    # find a person by their username
    %entries = $ldap->subSearch('ou=People,o=acmeinc', 'uid' => 'joeuser',
        'cn', 'mail', 'homeDirectory');

=cut

my %_scopes = ( 'base' => 0, 'one' => 1, 'sub' => 2 ); # map scope names to internal LDAP code

sub simpleSearch($$$@)
{
    my($self, $base, $scope, $condAttr, $condVal, @attrs) = @_;
    my $msgid = $self->{'nextMsgID'};
    $self->{'nextMsgID'} = ($msgid > 10000 ? $msgid - 10000 : $msgid + 1);
    my $socket = $self->{'socket'};

    $scope = $_scopes{$scope};
    defined $scope or return ();

    # send the request
    my $request = toBER(0x30,
        toBER(0x02, int2ber($msgid)),
        toBER(0x63, # search request
            toBER(0x04, $base), # search base
            toBER(0x0a, int2ber($scope)), toBER(0x0a, int2ber(0)), # use scope and never follow aliases
            toBER(0x02, int2ber(0)), toBER(0x02, int2ber(0)), # no size/time limits
            toBERBoolean(0), # we don't want types-only
            toBER(0x80 | 0x20 | 0x03, # filter type = AttributeValueAssertion
                toBER(0x04, $condAttr),
                toBER(0x04, $condVal)
                ),
            toBER(0x30, map { toBER(0x04, $_) } @attrs) # what we want back
            )
        );

    unless(send($socket, $request, 0)) { return (); }

    # listen for response
    my $done = 0;
    my @results;
    my $data = ''; # running buffer of data to parse
    while(not $done)
    {
        # read just enough to parse next response
        # this way the buffer is kept small and fast
        my($rbits) = ('');
        vec($rbits, fileno($socket), 1) = 1;

        select(my $rtmp = $rbits, undef, undef, $_timeout) or return (); # first wait with the timeout...
        recv($socket, my $chunk, 65536, 0);
        $data .= $chunk;

        # parser will leave incomplete data in buffer
        my @responses = parseBERTokens(\$data);

        # parse responses
        while(@responses)
        {
            my $responseTag = shift(@responses); # must use shift for proper order
            my $response = shift(@responses);

            $responseTag == 0x30 or return ();

            my($responseIDTag, $responseID, $opTag, $op) = parseBERTokens(\$response);
            ($responseIDTag == 0x02 and ber2int($responseID) == $msgid) or return ();

            # response type
            if($opTag == 0x65) { $done = 1; last; }
            if($opTag == 0x73) { next; } # skip reference responses
            $opTag == 0x64 or return ();

            my($resultDNTag, $resultDN, $attrsTag, $attrs) = parseBERTokens(\$op);
            $resultDNTag == 0x04 or return ();

            # process sets of attribute values
            $attrsTag == 0x30 or return ();
            my @attrs = parseBERTokens(\$attrs);
            my %attrHash;
            while(@attrs)
            {
                my $attr = pop(@attrs); # reverse pop
                my $attrTag = pop(@attrs);

                $attrTag == 0x30 or return ();
                my($attrNameTag, $attrName, $valuesTag, $values) = parseBERTokens(\$attr);

                $attrNameTag == 0x04 or return ();

                $valuesTag == 0x31 or return ();
                my $valuesOut = [];
                my @values = parseBERTokens(\$values);
                while(@values)
                {
                    push @$valuesOut, pop(@values);
                    pop(@values); # tag (should be 0x04)
                }

                $attrHash{lc $attrName} = $valuesOut;
            }

            push @results, $resultDN, { %attrHash };
        }
    }

    return @results;
}

=item subSearch(base, condAttr, condValue, returnAttrs...)

Shorthand form of C<simpleSearch(base, 'sub', ...)>.

=cut

sub subSearch($$$@)
{
    my($self, $base, $condAttr, $condVal, @attrs) = @_;
    return $self->simpleSearch($base, 'sub', $condAttr, $condVal, @attrs);
}

# BEGIN { warn "done compiling TinyLDAP\n"; }

=back

=head1 AUTHOR

Nick Matantsev (nick.matantsev at gmail.com)

=cut

1;

