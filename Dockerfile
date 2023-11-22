FROM centos:7

RUN yum --nogpgcheck -y install http://people.redhat.com/rsawhill/rpms/latest-rsawaroha-release.rpm

RUN yum --nogpgcheck -y install rhsecapi
