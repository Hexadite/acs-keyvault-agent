FROM ubuntu:18.04 as build-env

LABEL name="docker_acs_keyvault_agent" \
      version="2.0.1" \
      description="Build acs_keyvault_agent image" \
      maintainer="azlinux@microsoft.com" \
      repo="https://msazure.visualstudio.com/One/_git/Compute-Runtime-Tux-GenevaContainers"

# Use azure mirror for security reason
RUN sed -i "s://archive\.ubuntu\.com/://azure.archive.ubuntu.com/:" /etc/apt/sources.list

# Update cache and upgrade base packages
RUN apt-get update && apt-get upgrade -y

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends python-pip
RUN apt-get install -y --no-install-recommends git

# Clone acs-keyvault-agent github repository
WORKDIR /repo
RUN git clone https://github.com/Hexadite/acs-keyvault-agent.git
# Checkout version 
WORKDIR /repo/acs-keyvault-agent
RUN git checkout ca85044b7c4f4d11b43b9d318ddfb1d4016e0792

# Build runtime image
FROM python:3.9-slim

COPY --from=build-env /repo/acs-keyvault-agent .

# install requirements
RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python3", "/app/main.py" ]