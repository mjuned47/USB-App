usbredirserver_sources = [
    'usbredirserver.c',
]

executable('usbredirserver',
    sources : usbredirserver_sources,
    c_args : '-Wno-deprecated-declarations',
    install : true,
    install_dir: get_option('sbindir'),
    dependencies : usbredir_host_lib_dep)

install_man('usbredirserver.1')
