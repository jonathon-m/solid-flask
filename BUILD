load("@rules_python//python:python.bzl", "py_binary")
load("@my_deps//:requirements.bzl", "requirement")

py_binary(
    name = "solid_flask_main",
    srcs = ["solid_flask_main.py"],
    visibility = ["//visibility:public"],
    deps = [
        requirement("flask"),
        requirement("jinja2"),
        requirement("jwcrypto"),
        requirement("oic"),
    ],
)
