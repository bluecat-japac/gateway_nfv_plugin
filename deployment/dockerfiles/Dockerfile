FROM <trouble-shooting-image>
USER root

ENV PERMISSION_PATH    "./workflows/gateway_nfv_plugin/deployment/permissions.json"

# Copy workflows to gateway
COPY      --chown=flask:root     ./workflows             /builtin/workflows/
COPY      --chown=flask:root     ${PERMISSION_PATH}      /builtin

RUN if [ -s "/builtin/workflows/gateway_nfv_plugin/requirements.txt" ]; then \
       pip3 install -r "/builtin/workflows/gateway_nfv_plugin/requirements.txt" ; \
    fi && \
    echo DONE

USER flask
