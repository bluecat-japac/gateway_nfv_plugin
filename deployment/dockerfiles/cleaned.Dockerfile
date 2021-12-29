# Support remove "cpp" and "mirror" in container
ARG IMAGE=gateway_nfv_scheduler:<tag>
FROM $IMAGE
RUN   ln -s / /rootlink && \
      rm -rf /usr/lib/apt/methods/mirror* \
            /etc/alternatives/cpp \
            /usr/bin/cpp \
            /usr/lib/cpp  \
            /lib/cpp \
            /usr/share/doc/cpp \
            /var/lib/dpkg/alternatives/cpp
FROM scratch
COPY --from=0 /rootlink/ /
RUN rm -rf /rootlink
CMD ["/bin/bash"]
