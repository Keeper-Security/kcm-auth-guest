/*
 * Copyright (c) 2024 Keeper Security, Inc. All rights reserved.
 *
 * Unless otherwise agreed in writing, this software and any associated
 * documentation files (the "Software") may be used and distributed solely
 * in accordance with the Keeper Connection Manager EULA:
 *
 *     https://www.keepersecurity.com/termsofuse.html?t=k
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package com.keepersecurity.kcm.guest;

import inet.ipaddr.IPAddressString;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AbstractUser;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.UserGroup;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleUserGroup;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.apache.guacamole.properties.StringListProperty;

/**
 * AuthenticatinProvider implementation that automatically authenticates all
 * users as anonymous guests. Optionally, specific users may be excluded from
 * being considered guests based on originating IP address.
 */
public class GuestAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * The Guacamole server environment.
     */
    private static final Environment environment = LocalEnvironment.getInstance();

    /**
     * The default identifier of the group that all guest users should be
     * members of.
     */
    private static final String DEFAULT_GUEST_GROUP = "guests";

    /**
     * The name that should be displayed as each guest user's full name.
     */
    private static final String GUEST_FULL_NAME = "Demo User";

    /**
     * Property that specifies a comma-separated list of all IP addresses or
     * CIDR subnets that should NOT be considered guests. All other users will
     * be automatically authenticated as guest users. If not specified, all
     * users will be considered guests.
     */
    private static final StringListProperty NON_GUEST_NETWORKS = new StringListProperty() {

        @Override
        public String getName() {
            return "kcm-non-guest-networks";
        }

    };

    /**
     * Property that specifies the name of the group that should be applied to
     * all guest users. If not specified, all guest users will be members of
     * the group defined by {@link #DEFAULT_GUEST_GROUP}.
     */
    private static final StringGuacamoleProperty GUEST_GROUP = new StringGuacamoleProperty() {

        @Override
        public String getName() {
            return "kcm-guest-group";
        }

    };

    @Override
    public String getIdentifier() {
        return "kcm-guest";
    }

    /**
     * Returns whether the user that submitted the given authentication request
     * should be considered a guest user. This is determined purely based on
     * the originating IP address.
     *
     * @param request
     *     The HTTP request that the user submitted to authenticate.
     *
     * @return
     *     true if the user should be considered a guest user, false otherwise.
     *
     * @throws GuacamoleException
     *     If an error occurs while retrieving configuration properties that
     *     are factors in determining whether a user is a guest user.
     */
    private boolean isGuestUser(HttpServletRequest request) throws GuacamoleException {

        Collection<String> nonGuestNetworks = environment.getProperty(NON_GUEST_NETWORKS, Collections.<String>emptyList());
        for (String network : nonGuestNetworks) {

            // A user is a non-guest user only if their authentication request
            // originates from any of the defined non-guest networks/addresses
            if (new IPAddressString(network).contains(new IPAddressString(request.getRemoteAddr())))
                return false;

        }

        // All other users are guests
        return true;

    }

    /**
     * Returns the name of the group configured via the "kcm-guest-group"
     * property. If no such group has been configured, the default group name
     * defined by {@link #DEFAULT_GUEST_GROUP} is used.
     *
     * @return
     *     The name of the KCM guest group.
     *
     * @throws GuacamoleException
     *     If an error prevents reading the guest group name from
     *     guacamole.properties.
     */
    private String getGuestGroup() throws GuacamoleException {
        return environment.getProperty(GUEST_GROUP, DEFAULT_GUEST_GROUP);
    }

    @Override
    public AuthenticatedUser authenticateUser(final Credentials credentials)
            throws GuacamoleException {

        final HttpServletRequest request = credentials.getRequest();
        if (request != null && isGuestUser(request)) {

            // Pull name of guest group only during initial authentication
            // process (no need to refresh this during the session)
            final String guestGroup = getGuestGroup();

            // Generate an absolutely unique user identifier for this specific
            // session
            final String identifier = "guest-" + UUID.randomUUID().toString();

            // Authenticate all guests users as anonymous users who are members
            // of the pre-defined guest group
            return new AbstractAuthenticatedUser() {

                @Override
                public AuthenticationProvider getAuthenticationProvider() {
                    return GuestAuthenticationProvider.this;
                }

                @Override
                public Credentials getCredentials() {
                    return credentials;
                }

                @Override
                public Set<String> getEffectiveUserGroups() {
                    return Collections.singleton(guestGroup);
                }

                @Override
                public String getIdentifier() {
                    return identifier;
                }

                @Override
                public void setIdentifier(String identifier) {
                    throw new UnsupportedOperationException("Guest accounts are read-only.");
                }

            };
        }

        // Do not authenticate any other users - we care only about guest users
        return null;

    }

    @Override
    public UserContext getUserContext(final AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // As with the authentication portion of this, there is no need to
        // refresh group name during the session. It's sufficient to just pull
        // it once during authorization.
        final String guestGroup = getGuestGroup();

        // Provide pre-defined group for administrator convenience and a more
        // human-readable user name for aesthetics
        return new AbstractUserContext() {

            @Override
            public User self() {
                return new AbstractUser() {

                    @Override
                    public String getIdentifier() {
                        return authenticatedUser.getIdentifier();
                    }

                    @Override
                    public Map<String, String> getAttributes() {

                        // Display current user as "Demo User" after logging in
                        if (authenticatedUser.getAuthenticationProvider() == GuestAuthenticationProvider.this)
                            return Collections.singletonMap(User.Attribute.FULL_NAME, GUEST_FULL_NAME);

                        return Collections.emptyMap();

                    }

                };
            }

            @Override
            public Directory<UserGroup> getUserGroupDirectory() throws GuacamoleException {
                return new SimpleDirectory<>(new SimpleUserGroup(guestGroup));
            }

            @Override
            public AuthenticationProvider getAuthenticationProvider() {
                return GuestAuthenticationProvider.this;
            }

        };
    }

}
