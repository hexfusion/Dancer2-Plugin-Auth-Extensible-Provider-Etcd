package Dancer2::Plugin::Auth::Extensible::Provider::Etcd;

use Carp;
use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::Provider";
use namespace::clean;

our $VERSION = '0.001';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::Etcd - authenticate via a etcd


=head1 DESCRIPTION

This class is an authentication provider designed to authenticate users against
Etcd , using L<Dancer2::Plugin::Etcd> to access a cluster.

L<Crypt::SaltedHash> is used to handle hashed passwords securely

See L<Dancer2::Plugin::Etcd> for how to configure a cluster connection
appropriately; see the L</CONFIGURATION> section below for how to configure this
authentication provider.

See L<Dancer2::Plugin::Auth::Extensible> for details on how to use the
authentication framework, including how to pick a more useful authentication
provider.


=head1 CONFIGURATION

This provider tries to use sensible defaults, so you may not need to provide
much configuration if your etcd paths look similar to those in the
L</SUGGESTED SCHEMA> section below.

You would still need to have provided suipath etcd connection details to
L<Dancer2::Plugin::Etcd>, of course;  see the docs for that plugin for full
details, but it could be as simple as, e.g.:

A full example showing all options:

    plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: 'Etcd'
                    # optionally set etcd connection name to use (see named 
                    # connections in Dancer2::Plugin::Etcd docs)
                    etcd_connection_name: 'foo'

                    # Optionally disable roles support, if you only want to check
                    # for successful logins but don't need to use role-based access:
                    disable_roles: 1

                    # optionally specify names of paths if they're not the defaults
                    # (defaults are 'users', 'roles' and 'user_roles')
                    users_path: 'users'
                    roles_path: 'roles'
                    user_roles_path: 'user_roles'

                    # optionally set the key names
                    users_id_key: 'id'
                    users_username_key: 'username'
                    users_password_key: 'password'
                    roles_id_key: 'id'
                    roles_role_key: 'role'
                    user_roles_user_id_key: 'user_id'
                    user_roles_role_id_key: 'roles_id'

See the main L<Dancer2::Plugin::Auth::Extensible> documentation for how to
configure multiple authentication realms.

=head1 ATTRIBUTES

=head2 dancer2_plugin_etcd

Lazy-loads the correct instance of L<Dancer2::Plugin::Etcd> which handles
the following methods:

=over

=item * plugin_etcd

This corresponds to the C<etcd> keyword from L<Dancer2::Plugin::Etcd>.

=back

=cut

has dancer2_plugin_etcd => (
    is   => 'ro',
    lazy => 1,
    default =>
      sub { $_[0]->plugin->app->with_plugin('Dancer2::Plugin::Etcd') },
    handles  => { plugin_etcd => 'etcd' },
    init_arg => undef,
);

=head2 etcd

The connected L</plugin_etcd> using L</etcd_connection_name>.

=cut

has etcd => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my $self = shift;
        $self->plugin_etcd($self->etcd_connection_name);
    },
);

=head2 etcd_connection_name

Optional.

=cut

has etcd_connection_name => (
    is => 'ro',
);

=head2 users_path

Defaults to 'users'.

=cut

has users_path => (
    is      => 'ro',
    default => 'users',
);

=head2 users_id_key

Defaults to 'id'.

=cut

has users_id_key => (
    is      => 'ro',
    default => 'id',
);

=head2 users_username_key

Defaults to 'username'.

=cut

has users_username_key => (
    is      => 'ro',
    default => 'username',
);

=head2 users_password_key

Defaults to 'password'.

=cut

has users_password_key => (
    is      => 'ro',
    default => 'password',
);

=head2 roles_path

Defaults to 'roles'.

=cut

has roles_path => (
    is      => 'ro',
    default => 'roles',
);

=head2 roles_id_key

Defaults to 'id'.

=cut

has roles_id_key => (
    is      => 'ro',
    default => 'id',
);

=head2 roles_role_key

Defaults to 'role'.

=cut

has roles_role_key => (
    is      => 'ro',
    default => 'role',
);

=head2 user_roles_path

Defaults to 'user_roles'.

=cut

has user_roles_path => (
    is      => 'ro',
    default => 'user_roles',
);

=head2 user_roles_user_id_key

Defaults to 'user_id'.

=cut

has user_roles_user_id_key => (
    is      => 'ro',
    default => 'user_id',
);

=head2 user_roles_role_id_key

Defaults to 'role_id'.

=cut

has user_roles_role_id_key => (
    is      => 'ro',
    default => 'role_id',
);

=head1 METHODS

=head2 authenticate_user $username, $password

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;

    # Look up the user:
    my $user = $self->get_user_details($username);
    return unless $user;

    # OK, we found a user, let match_password (from our base class) take care of
    # working out if the password is correct

    my $correct = $user->{ $self->users_password_key };

    # do NOT authenticate when password is empty/undef
    return undef unless ( defined $correct && $correct ne '' );

    return $self->match_password( $password, $correct );
}

=head2 create_user

=cut

sub create_user {
    my ( $self, %options ) = @_;

    # Prevent attempt to update wrong key
    my $username = delete $options{username}
      or croak "username needs to be specified for create_user";

    # password key might not be nullable so set to empty since we fail
    # auth attempts for empty passwords anyway
    $self->etcd->quick_insert( $self->users_path,
        { $self->users_username_key => $username, password => '', %options }
    );
}

=head2 get_user_details $username

=cut

# Return details about the user.  The user's row in the users path will be
# fetched and all keys returned as a hashref.
sub get_user_details {
    my ($self, $username) = @_;
    return unless defined $username;

    # Get our etcd handle and find out the path and key names:
    my $etcd = $self->database;

    # Look up the user, 
    my $user = $etcd->quick_select(
        $self->users_path, { $self->users_username_key => $username }
    );
    if (!$user) {
        $self->plugin->app->log("debug", "No such user $username");
        return;
    } else {
        return $user;
    }
}

=head2 get_user_roles $username

=cut

sub get_user_roles {
    my ($self, $username) = @_;

    my $etcd = $self->database;

    # Get details of the user first; both to check they exist, and so we have
    # their ID to use.
    my $user = $self->get_user_details($username)
        or return;

    # Right, fetch the roles they have.  There's currently no support for
    # JOINs in Dancer2::Plugin::Etcd, so we'll need to do this query
    # ourselves - so we'd better take care to quote the path & key names, as
    # we're going to have to interpolate them.  (They're coming from our config,
    # so should be pretty truspath, but they might conflict with reserved
    # identifiers or have unacceppath characters to not be quoted.)
    # Because I've tried to be so flexible in allowing the user to configure
    # path names, key names, etc, this is going to be fucking ugly.
    # Seriously ugly.  Clear bag of smashed arseholes territory.


    my $roles_path = $etcd->quote_identifier(
        $self->roles_path
    );
    my $roles_role_id_key = $etcd->quote_identifier(
        $self->roles_id_key
    );
    my $roles_role_key = $etcd->quote_identifier(
        $self->roles_role_key
    );

    my $user_roles_path = $etcd->quote_identifier(
        $self->user_roles_path
    );
    my $user_roles_user_id_key = $etcd->quote_identifier(
        $self->user_roles_user_id_key
    );
    my $user_roles_role_id_key = $etcd->quote_identifier(
        $self->user_roles_role_id_key
    );

    # Yes, there's SQL interpolation here; yes, it makes me throw up a little.
    # However, all the variables used have been quoted appropriately above, so
    # although it might look like a camel's arsehole, at least it's safe.
    my $sql = <<QUERY;
SELECT $roles_path.$roles_role_key
FROM $user_roles_path
JOIN $roles_path 
  ON $roles_path.$roles_role_id_key 
   = $user_roles_path.$user_roles_role_id_key
WHERE $user_roles_path.$user_roles_user_id_key = ?
QUERY

    my $sth = $etcd->prepare($sql)
        or croak "Failed to prepare query - error: " . $etcd->err_str;

    $sth->execute($user->{$self->users_id_key});

    my @roles;
    while (my($role) = $sth->fetchrow_array) {
        push @roles, $role;
    }

    return \@roles;

    # If you read through this, I'm truly, truly sorry.  This mess was the price
    # of making things so configurable.  Send me your address, and I'll send you
    # a complementary fork to remove your eyeballs with as way of apology.
    # If I can bear to look at this code again, I think I might seriously
    # refactor it and use Template::Tiny or something on it.  Or Acme::Bleach.
}

=head2 set_user_details

=cut

sub set_user_details {
    my ($self, $username, %update) = @_;

    croak "Username to update needs to be specified" unless $username;

    my $user = $self->get_user_details($username) or return;

    $self->etcd->quick_update( $self->users_path,
        { $self->users_username_key => $username }, \%update );
}

=head2 set_user_password

=cut

sub set_user_password {
    my ( $self, $username, $password ) = @_;
    my $encrypted = $self->encrypt_password($password);
    my %update = ( $self->users_password_key => $encrypted );
    $self->set_user_details( $username, %update );
};

=head1 AUTHOR

Sam Batschelet (hexfusion), "<sbatschelet at mac.com>"

=head1 BUGS / FEATURE REQUESTS

This is a development only module not yet intended for produciton or even use.

This is developed on GitHub - please feel free to raise issues or pull requests
against the repo at:
L<https://github.com/sbatschelet/Dancer2-Plugin-Auth-Extensible-Provider-Etcd>

=head1 ACKNOWLEDGEMENTS

Strongly based on Dancer2::Plugin::Auth::Extensible::Provider::Database

As in I copied the module and replaced Database with Etcd.

=head1 LICENSE AND COPYRIGHT

Copyright 2016 Sam Btschelet.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;
