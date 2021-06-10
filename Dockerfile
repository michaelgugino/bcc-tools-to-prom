FROM registry.ci.openshift.org/ocp/4.7:tools

# Make sure to maintain alphabetical ordering when adding new packages.
RUN INSTALL_PKGS="\
    kernel-devel-4.18.0-240.22.1.el8_3.x86_64 \
    bcc-tools \
    " && \
    yum -y install --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS && \
    yum clean all && rm -rf /var/cache/*
