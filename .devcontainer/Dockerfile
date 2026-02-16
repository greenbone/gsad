FROM registry.community.greenbone.net/community/gvm-libs:stable

ARG DEBIAN_FRONTEND=noninteractive

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# install dependencies
RUN --mount=type=bind,source=.github,target=/source/ \
    sh /source/install-dependencies.sh /source/build-dependencies.list
RUN apt-get install -y --no-install-recommends \
    clang-format \
    sudo \
    gdb \
    libcgreen1-dev

# add non-root user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

CMD /bin/bash
