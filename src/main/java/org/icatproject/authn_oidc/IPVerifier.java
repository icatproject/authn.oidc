package org.icatproject.authn_oidc;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.icatproject.authentication.AuthnException;
import org.icatproject.utils.AddressChecker;
import org.icatproject.utils.AddressCheckerException;
import org.jboss.logging.Logger;

import java.net.HttpURLConnection;
import java.util.Optional;

/**
 * The {@code IPVerifier} class is responsible for verifying the IP address
 * of incoming requests using the {@link AddressChecker} ICAT utility.
 * <p>
 * It checks if an IP address is configured, initialises an AddressChecker,
 * and verifies whether the IP from a request is allowed to proceed.
 * </p>
 */
@ApplicationScoped
public class IPVerifier {

    private static final Logger logger = Logger.getLogger(IPVerifier.class);

    @Inject
    @ConfigProperty(name = "ip")
    Optional<String> ipAddresses;

    private AddressChecker addressChecker;

    /** Constructor that creates an instance of address checker if any IPs are present,
     * and registers them with it */
    @PostConstruct
    public void init() {
        logger.info("Checking IPs");
        if (ipAddresses.isPresent()) {
            try {
                logger.info("Initialising AddressChecker with IP: " + ipAddresses);
                // If ipAddresses is present, create an AddressChecker
                addressChecker = new AddressChecker(ipAddresses.get());
            } catch (Exception e) {
                logger.error("Problem creating AddressChecker with IP: " + ipAddresses, e);
                throw new IllegalStateException("Invalid IP configuration", e);
            }
        } else {
            logger.info("No IP configured, AddressChecker will not be initialized.");
        }
    }

    /** Method that checks if the IPs in the request are in the address checker */
    public void CheckIPs(String ips) throws AuthnException {
        logger.info("Checking addressChecker");
        if (addressChecker != null) {
            try {
                if (ips == null) {
                    logger.error("An IP address must be provided");
                    throw new AuthnException(HttpURLConnection.HTTP_BAD_REQUEST, "An IP address must be provided");
                }
                if (!addressChecker.check(ips)) {
                    throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "authn_oidc does not allow log in from " +
                            "your IP address " + ips);
                }
            } catch (AddressCheckerException e) {
                throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
            }
        }
    }
}
