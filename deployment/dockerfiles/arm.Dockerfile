FROM <trouble-shooting-image>
USER root

ENV PERMISSION_PATH    "./workflows/gateway_nfv_plugin/deployment/permissions.json"

# Copy workflows to gateway
COPY      --chown=flask:root     ./workflows             /builtin/workflows/
COPY      --chown=flask:root     ${PERMISSION_PATH}      /builtin

# Fix issue 'no matching distribution found for suds-jurko'
RUN pip3 install --upgrade --no-cache-dir setuptools==57.5.0

RUN if [ -s "/builtin/workflows/gateway_nfv_plugin/requirements_arm64.txt" ]; then \
       pip3 install -r "/builtin/workflows/gateway_nfv_plugin/requirements_arm64.txt" ; \
    fi && \
    echo DONE

USER flask
