The `dkms-packaging` directory includes all the files required by DKMS in order to create Jool packages for some of the most popular Linux distributions, that could be used as a template, helping users to create RPM and Debian packages for others distros.

# How to Build DSC/DEB/RPM Packages Using DKMS

1. Download the official release .ZIP file (from http://jool.mx/en/download.html or https://github.com/NICMx/Jool/) and extract the Jool directories. It is required to change the name of Jool directory using the following format: jool-VERSION (e.g. jool-3.5.3). The name "jool" should start with lowercase, followed by a hyphen and the version.

2. Install all the requirements for Jool (including DKMS). Debian also requires debhelper in order to build the debian package. 

3. If you want to build a RPM package, copy the `rpm/jool-dkms-mkrpm.spec` file into Jool directory. If you want to build a deb/dsc debian package, copy the `jool-dkms-mkdeb/` or `jool-dkms-mkdsc/` directories from `deb/` into Jool. 

4. Copy the Jool directory into `/usr/src/`.

5. Add Jool to the DKMS tree:

	dkms add -m jool -v <jool_version>

6. Build Jool

	dkms build -m jool -v <jool_version>

7. Create the package rpm/deb/dsc package:

        RPM:    dkms mkrpm -m jool -v <jool_version> --source-only
        DEB:    dkms mkdeb -m jool -v <jool_version> --source-only
        DSC:    dkms mkdsc -m jool -v <jool_version> --source-only
		
NOTE: If you want to build the dsc package for a specific Ubuntu release, it is necessary to modify the following line in 'deb/jool-dkms-mkdsc/debian/changelog' file:

"DEBIAN_PACKAGE-dkms (MODULE_VERSION) unstable; urgency=low"

replacing 'unstable' with the corresponding release codename (trusty, xenial, zesty, etc). 
