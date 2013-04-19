/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

This file is part of .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions
and limitations under the License.
*****************************************************************************/

struct udt_epoll_args {
    int efd;
    int signal_fd;
};


void *epoll_signal_thread(void *my_args)
{
    struct udt_epoll_args *args = (struct udt_epoll_args*)my_args;
    std::set<UDTSOCKET> udt_read_fds;
    char sink[1];
    int ret;

    while (true) {
        ret = UDT::epoll_wait(args->efd, &udt_read_fds, NULL, -1);
        if (ret < 1 || udt_read_fds.size() < 1)
            break;
        write(args->signal_fd, "", 1);
    }
}


int udt_epoll(int udt_efd, pthread_t *signal_thread)
{
    int proxy_fd[2];
    struct udt_epoll_args *args;

    args = (struct udt_epoll_args*)malloc(sizeof(struct udt_epoll_args));

    pipe(proxy_fd);

    args->signal_fd = proxy_fd[1];
    args->efd = udt_efd;

    pthread_create(signal_thread, NULL, epoll_signal_thread, (void*)args);

    fcntl(proxy_fd[0], F_SETFL, O_NONBLOCK);

    return proxy_fd[0];
}

int udt_epoll_wait(int udt_efd, int signal_sink, set<UDTSOCKET>* udt_read_fds)
{
    UDT::epoll_wait(udt_efd, &udt_read_fds, NULL, -1,  &read_fds);
    read(signal_sink, sink, 1);
}

