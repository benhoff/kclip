# pytest -q
import os, fcntl, ctypes, errno, pytest, select
from contextlib import contextmanager
from pathlib import Path

DEV_PATH = "/dev/kclip"

pytestmark = pytest.mark.skipif(
    not os.path.exists(DEV_PATH),
    reason=f"{DEV_PATH} not found (module not loaded?)",
)

# ===== UAPI mirror (ctypes) =====
KCLIP_ABI_VERSION = 1
KCLIP_MIME_MAX = 128
KCLIP_COMM_MAX = 16

# publish flags
KCLIP_PUBLISH_F_REQUIRE_SEALS = 1 << 0
KCLIP_PUBLISH_F_PRIVATE       = 1 << 1

# fetch flags
KCLIP_FETCH_F_NONBLOCK        = 1 << 0
KCLIP_FETCH_F_PEEK            = 1 << 1
KCLIP_FETCH_F_POP             = 1 << 2
KCLIP_FETCH_F_GET_PART_FDS    = 1 << 3

# part flags
KCLIP_PART_F_PRIMARY          = 1 << 0

# limits policy flags
KCLIP_LIMITS_F_EVICT_LRU      = 1 << 0
KCLIP_LIMITS_F_REJECT         = 1 << 1


class kclip_mime(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16),
        ("s", ctypes.c_char * KCLIP_MIME_MAX),
    ]


class kclip_meta(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("uid", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * KCLIP_COMM_MAX),
    ]


class kclip_part(ctypes.Structure):
    _fields_ = [
        ("mime", kclip_mime),
        ("size", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("memfd_fd", ctypes.c_int32),
        ("_pad", ctypes.c_uint32),
    ]


class kclip_msg_publish(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("parts_count", ctypes.c_uint32),
        ("flags", ctypes.c_uint64),
        ("parts_ptr", ctypes.c_uint64),  # __aligned_u64
    ]


class kclip_msg_fetch(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),

        ("out_seqno", ctypes.c_uint64),
        ("out_total_size", ctypes.c_uint64),
        ("out_parts_count", ctypes.c_uint32),
        ("_pad0", ctypes.c_uint32),

        ("out_meta", kclip_meta),

        ("out_parts_cap", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("out_parts_ptr", ctypes.c_uint64),
    ]


class kclip_head(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad0", ctypes.c_uint32),
        ("out_seqno", ctypes.c_uint64),
        ("out_total_size", ctypes.c_uint64),
        ("out_parts_count", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("out_primary_mime", kclip_mime),
        ("out_meta", kclip_meta),
    ]


class kclip_limits(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("scope", ctypes.c_uint32),      # 1 = per-slot
        ("scope_id", ctypes.c_uint32),
        ("max_msg_bytes", ctypes.c_uint64),
        ("max_parts", ctypes.c_uint32),
        ("max_depth", ctypes.c_uint32),
        ("max_bytes_total", ctypes.c_uint64),
        ("policy_flags", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
    ]


class kclip_msg_ack(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("seqno", ctypes.c_uint64),
    ]


class kclip_msg_consume(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("seqno", ctypes.c_uint64),
    ]


class kclip_slot_entry(ctypes.Structure):
    _fields_ = [
        ("slot_id", ctypes.c_uint32),
        ("depth", ctypes.c_uint32),
        ("bytes", ctypes.c_uint64),
    ]


class kclip_slot_list(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("in_cap", ctypes.c_uint32),
        ("out_count", ctypes.c_uint32),
        ("entries_ptr", ctypes.c_uint64),
    ]


class kclip_stats(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("depth", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
        ("enqueued", ctypes.c_uint64),
        ("dequeued", ctypes.c_uint64),
        ("dropped", ctypes.c_uint64),
    ]


class kclip_eventfd(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("eventfd", ctypes.c_int32),
        ("_pad2", ctypes.c_uint32),
    ]


class kclip_bind_slot(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("struct_size", ctypes.c_uint16),
        ("slot", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
    ]


# ===== ioctl number helpers (asm-generic) =====
_IOC_NRBITS   = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS  = 2
_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2


def _IOC(dir_, type_, nr, size):
    return (dir_  << _IOC_DIRSHIFT)  | \
           (type_ << _IOC_TYPESHIFT) | \
           (nr    << _IOC_NRSHIFT)   | \
           (size  << _IOC_SIZESHIFT)


def _IOW(type_, nr, struct_cls):
    return _IOC(_IOC_WRITE, type_, nr, ctypes.sizeof(struct_cls))


def _IOWR(type_, nr, struct_cls):
    return _IOC(_IOC_READ | _IOC_WRITE, type_, nr, ctypes.sizeof(struct_cls))


KCLIP_IOC_MAGIC       = ord('U')
KCLIP_IOC_MSG_PUBLISH = _IOW (KCLIP_IOC_MAGIC, 0x01, kclip_msg_publish)
KCLIP_IOC_MSG_FETCH   = _IOWR(KCLIP_IOC_MAGIC, 0x02, kclip_msg_fetch)
KCLIP_IOC_MSG_ACK     = _IOW (KCLIP_IOC_MAGIC, 0x03, kclip_msg_ack)
KCLIP_IOC_HEAD        = _IOWR(KCLIP_IOC_MAGIC, 0x04, kclip_head)
KCLIP_IOC_SLOT_LIST   = _IOWR(KCLIP_IOC_MAGIC, 0x05, kclip_slot_list)
KCLIP_IOC_LIMITS_GET  = _IOWR(KCLIP_IOC_MAGIC, 0x06, kclip_limits)
KCLIP_IOC_LIMITS_SET  = _IOW (KCLIP_IOC_MAGIC, 0x07, kclip_limits)
KCLIP_IOC_STATS_GET   = _IOWR(KCLIP_IOC_MAGIC, 0x08, kclip_stats)
KCLIP_IOC_EVENTFD     = _IOW (KCLIP_IOC_MAGIC, 0x09, kclip_eventfd)
KCLIP_IOC_BIND_SLOT   = _IOW (KCLIP_IOC_MAGIC, 0x0A, kclip_bind_slot)
KCLIP_IOC_MSG_CONSUME = _IOW (KCLIP_IOC_MAGIC, 0x0B, kclip_msg_consume)


# ===== shared helpers =====
def memfd_create(name: str, cloexec=True):
    if hasattr(os, "memfd_create"):
        flags = os.MFD_CLOEXEC if cloexec else 0
        return os.memfd_create(name, flags)
    # fallback via syscall (x86_64)
    import ctypes.util as _ut
    libc = ctypes.CDLL(_ut.find_library("c"), use_errno=True)
    SYS_memfd_create = 319
    fd = libc.syscall(SYS_memfd_create, name.encode(), int(cloexec))
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return fd


def eventfd_create(initval=0, cloexec=True):
    flags = getattr(os, "EFD_CLOEXEC", 0) if cloexec else 0
    if hasattr(os, "eventfd"):
        return os.eventfd(initval, flags)
    import ctypes.util as _ut
    libc = ctypes.CDLL(_ut.find_library("c"), use_errno=True)
    SYS_eventfd2 = 290
    fd = libc.syscall(SYS_eventfd2, initval, flags)
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return fd


def ioc(devfd, req, struct_obj):
    buf = (ctypes.c_char * ctypes.sizeof(struct_obj)).from_buffer(struct_obj)
    fcntl.ioctl(devfd, req, buf)


def set_mime(mime_struct: kclip_mime, b: bytes):
    n = min(len(b), KCLIP_MIME_MAX)
    mime_struct.len = n
    base = ctypes.addressof(mime_struct)
    off  = kclip_mime.s.offset
    ctypes.memset(base + off, 0, KCLIP_MIME_MAX)
    ctypes.memmove(base + off, b, n)


def get_mime(mime_struct: kclip_mime) -> bytes:
    n = min(mime_struct.len, KCLIP_MIME_MAX)
    return ctypes.string_at(ctypes.addressof(mime_struct) + kclip_mime.s.offset, n)


def make_part(memfd, data: bytes, flags=KCLIP_PART_F_PRIMARY):
    # ensure memfd has the bytes
    os.ftruncate(memfd, len(data))
    os.pwrite(memfd, data, 0)
    p = kclip_part()
    set_mime(p.mime, b"text/plain")
    p.size = len(data)
    p.flags = flags
    p.memfd_fd = memfd
    return p


def make_parts_array(*parts):
    Arr = kclip_part * len(parts)
    arr = Arr()
    for i, p in enumerate(parts):
        arr[i] = p
    return arr


def publish(devfd, slot, parts_arr, flags=0):
    pub = kclip_msg_publish()
    pub.abi_version = KCLIP_ABI_VERSION
    pub.struct_size = ctypes.sizeof(kclip_msg_publish)
    pub.slot = slot
    pub.parts_count = len(parts_arr)
    pub.flags = flags
    pub.parts_ptr = ctypes.addressof(parts_arr)
    ioc(devfd, KCLIP_IOC_MSG_PUBLISH, pub)


def fetch(devfd, slot, flags=0, out_cap=0):
    f = kclip_msg_fetch()
    f.abi_version = KCLIP_ABI_VERSION
    f.struct_size = ctypes.sizeof(kclip_msg_fetch)
    f.slot = slot
    f.flags = flags
    if out_cap:
        PartArray = kclip_part * out_cap
        out_parts = PartArray()
        f.out_parts_cap = out_cap
        f.out_parts_ptr = ctypes.addressof(out_parts)
    else:
        out_parts = None
    ioc(devfd, KCLIP_IOC_MSG_FETCH, f)
    return f, out_parts


def ack(devfd, slot, seqno):
    a = kclip_msg_ack()
    a.abi_version = KCLIP_ABI_VERSION
    a.struct_size = ctypes.sizeof(kclip_msg_ack)
    a.slot = slot
    a.seqno = seqno
    ioc(devfd, KCLIP_IOC_MSG_ACK, a)


def consume(devfd, slot, seqno):
    c = kclip_msg_consume()
    c.abi_version = KCLIP_ABI_VERSION
    c.struct_size = ctypes.sizeof(kclip_msg_consume)
    c.slot = slot
    c.seqno = seqno
    ioc(devfd, KCLIP_IOC_MSG_CONSUME, c)


def bind_slot(devfd, slot):
    bs = kclip_bind_slot()
    bs.abi_version = KCLIP_ABI_VERSION
    bs.struct_size = ctypes.sizeof(kclip_bind_slot)
    bs.slot = slot
    ioc(devfd, KCLIP_IOC_BIND_SLOT, bs)


def head(devfd, slot):
    h = kclip_head()
    h.abi_version = KCLIP_ABI_VERSION
    h.struct_size = ctypes.sizeof(kclip_head)
    h.slot = slot
    ioc(devfd, KCLIP_IOC_HEAD, h)
    return h


def slot_list(devfd, in_cap):
    hdr = kclip_slot_list()
    hdr.abi_version = KCLIP_ABI_VERSION
    hdr.struct_size = ctypes.sizeof(kclip_slot_list)
    hdr.in_cap = in_cap
    if in_cap:
        Arr = kclip_slot_entry * in_cap
        entries = Arr()
        hdr.entries_ptr = ctypes.addressof(entries)
    else:
        entries = None
        hdr.entries_ptr = 0
    ioc(devfd, KCLIP_IOC_SLOT_LIST, hdr)
    return hdr, entries


def get_limits(devfd, slot):
    lim = kclip_limits()
    lim.abi_version = KCLIP_ABI_VERSION
    lim.struct_size = ctypes.sizeof(kclip_limits)
    lim.scope = 1
    lim.scope_id = slot
    ioc(devfd, KCLIP_IOC_LIMITS_GET, lim)
    return lim


def set_limits(devfd, slot, **overrides):
    lim = get_limits(devfd, slot)
    for k, v in overrides.items():
        setattr(lim, k, v)
    lim.abi_version = KCLIP_ABI_VERSION
    lim.struct_size = ctypes.sizeof(kclip_limits)
    lim.scope = 1
    lim.scope_id = slot
    ioc(devfd, KCLIP_IOC_LIMITS_SET, lim)
    return get_limits(devfd, slot)


@contextmanager
def temporary_limits(devfd, slot, **overrides):
    orig = get_limits(devfd, slot)
    try:
        if overrides:
            set_limits(devfd, slot, **overrides)
        yield get_limits(devfd, slot)
    finally:
        set_limits(
            devfd,
            slot,
            max_msg_bytes=orig.max_msg_bytes,
            max_parts=orig.max_parts,
            max_depth=orig.max_depth,
            max_bytes_total=orig.max_bytes_total,
            policy_flags=orig.policy_flags,
        )


def drain_slot(devfd, slot=0):
    """Pop everything (nonblocking) to leave a clean slate."""
    while True:
        f = kclip_msg_fetch()
        f.abi_version = KCLIP_ABI_VERSION
        f.struct_size = ctypes.sizeof(kclip_msg_fetch)
        f.slot = slot
        f.flags = KCLIP_FETCH_F_NONBLOCK | KCLIP_FETCH_F_POP
        try:
            ioc(devfd, KCLIP_IOC_MSG_FETCH, f)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                break
            raise


def stats_get(devfd, slot):
    st = kclip_stats()
    st.abi_version = KCLIP_ABI_VERSION
    st.struct_size = ctypes.sizeof(kclip_stats)
    st.slot = slot
    ioc(devfd, KCLIP_IOC_STATS_GET, st)
    return st


def eventfd_config(devfd, slot, eventfd_no):
    ev = kclip_eventfd()
    ev.abi_version = KCLIP_ABI_VERSION
    ev.struct_size = ctypes.sizeof(kclip_eventfd)
    ev.slot = slot
    ev.eventfd = eventfd_no
    ioc(devfd, KCLIP_IOC_EVENTFD, ev)


# ===== pytest fixtures =====
@pytest.fixture(scope="module")
def devfd():
    fd = os.open(DEV_PATH, os.O_RDWR)
    try:
        yield fd
    finally:
        os.close(fd)


@pytest.fixture(autouse=True)
def clean_slot(devfd):
    drain_slot(devfd, 0)
    yield
    drain_slot(devfd, 0)


# ===== Tests: basic round-trip (from original simple file) =====
def test_publish_fetch_peek_and_pop(devfd):
    mfd = memfd_create("kclip-part")
    parts = make_parts_array(make_part(mfd, b"hello\n"))

    publish(devfd, 0, parts)

    h = head(devfd, 0)
    seq = h.out_seqno
    assert seq > 0
    assert h.out_total_size == 6
    assert h.out_parts_count == 1
    assert get_mime(h.out_primary_mime) == b"text/plain"

    f, out_parts = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK, out_cap=1)
    assert f.out_seqno == seq
    assert f.out_total_size == 6
    assert f.out_parts_count == 1
    assert out_parts[0].size == 6
    assert out_parts[0].memfd_fd == -1  # no GET_PART_FDS

    f2, _ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    assert f2.out_seqno == seq

    h2 = head(devfd, 0)
    assert h2.out_seqno == 0

    os.close(mfd)


def test_fetch_get_part_fds_returns_data(devfd):
    payload = b"abc123\n"
    mfd = memfd_create("kclip-part2")
    parts = make_parts_array(make_part(mfd, payload))
    publish(devfd, 0, parts)

    f, out_parts = fetch(
        devfd, 0, flags=KCLIP_FETCH_F_PEEK | KCLIP_FETCH_F_GET_PART_FDS, out_cap=1
    )

    fd_from_kernel = out_parts[0].memfd_fd
    assert fd_from_kernel >= 0
    got = os.read(fd_from_kernel, 4096)
    assert got.startswith(payload)
    os.close(fd_from_kernel)

    fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    os.close(mfd)


def test_nonblock_fetch_on_empty_returns_eagain(devfd):
    with pytest.raises(OSError) as ei:
        fetch(devfd, 0, flags=KCLIP_FETCH_F_NONBLOCK)
    assert ei.value.errno == errno.EAGAIN


# ===== Tests: publish path validation =====
def test_publish_parts_count_zero(devfd):
    Arr = kclip_part * 0
    arr = Arr()
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr)
    assert ex.value.errno == errno.EINVAL


def test_publish_parts_count_gt_max_parts(devfd):
    with temporary_limits(devfd, 0, max_parts=1):
        mfd1 = memfd_create("p1"); p1 = make_part(mfd1, b"a")
        mfd2 = memfd_create("p2"); p2 = make_part(mfd2, b"b")
        arr = make_parts_array(p1, p2)
        with pytest.raises(OSError) as ex:
            publish(devfd, 0, arr)
        assert ex.value.errno == errno.EINVAL
        os.close(mfd1); os.close(mfd2)


def test_publish_part_size_zero(devfd):
    mfd = memfd_create("zero")
    p = kclip_part()
    set_mime(p.mime, b"text/plain")
    p.size = 0
    p.flags = KCLIP_PART_F_PRIMARY
    p.memfd_fd = mfd
    arr = make_parts_array(p)
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr)
    assert ex.value.errno == errno.EINVAL
    os.close(mfd)


def test_publish_cumulative_size_gt_max_msg_bytes(devfd):
    with temporary_limits(devfd, 0, max_msg_bytes=4):
        mfd1 = memfd_create("a"); p1 = make_part(mfd1, b"aa")
        mfd2 = memfd_create("b"); p2 = make_part(mfd2, b"bbb")
        arr = make_parts_array(p1, p2)
        with pytest.raises(OSError) as ex:
            publish(devfd, 0, arr)
        assert ex.value.errno in (errno.E2BIG, errno.EINVAL)
        os.close(mfd1); os.close(mfd2)


def test_publish_mime_len_gt_max(devfd):
    mfd = memfd_create("mime")
    p = make_part(mfd, b"x")
    p.mime.len = KCLIP_MIME_MAX + 1  # simulate oversize len
    arr = make_parts_array(p)
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr)
    assert ex.value.errno == errno.EINVAL
    os.close(mfd)


# ===== memfd validation =====
def test_publish_non_memfd_regular_file(devfd):
    fd = os.open(str(Path(__file__).resolve().parents[1] / "kclip.c"), os.O_RDONLY)
    p = kclip_part()
    set_mime(p.mime, b"text/plain")
    p.size = 2
    p.flags = KCLIP_PART_F_PRIMARY
    p.memfd_fd = fd
    arr = make_parts_array(p)
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr)
    assert ex.value.errno == errno.EINVAL
    os.close(fd)


def test_publish_non_memfd_pipe_fd(devfd):
    r, w = os.pipe()
    try:
        p = kclip_part()
        set_mime(p.mime, b"text/plain")
        p.size = 1
        p.flags = KCLIP_PART_F_PRIMARY
        p.memfd_fd = r
        arr = make_parts_array(p)
        with pytest.raises(OSError) as ex:
            publish(devfd, 0, arr)
        assert ex.value.errno == errno.EINVAL
    finally:
        os.close(r); os.close(w)


def test_publish_invalid_fd(devfd):
    bad_fd = 0x7fffffff
    p = kclip_part()
    set_mime(p.mime, b"text/plain")
    p.size = 1
    p.flags = KCLIP_PART_F_PRIMARY
    p.memfd_fd = bad_fd
    arr = make_parts_array(p)
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr)
    assert ex.value.errno == errno.EBADF


def test_publish_with_require_seals_returns_eopnotsupp(devfd):
    mfd = memfd_create("sealed?")
    p = make_part(mfd, b"hello")
    arr = make_parts_array(p)
    with pytest.raises(OSError) as ex:
        publish(devfd, 0, arr, flags=KCLIP_PUBLISH_F_REQUIRE_SEALS)
    assert ex.value.errno in (errno.EOPNOTSUPP, errno.EINVAL)
    os.close(mfd)


# ===== limits & eviction =====
def test_eviction_policy_evict_lru(devfd):
    with temporary_limits(
        devfd,
        0,
        max_parts=8,
        max_depth=128,
        max_msg_bytes=64,
        max_bytes_total=8,
        policy_flags=KCLIP_LIMITS_F_EVICT_LRU,
    ):
        mfd1 = memfd_create("m1"); p1 = make_part(mfd1, b"aaaa")
        mfd2 = memfd_create("m2"); p2 = make_part(mfd2, b"bbbb")
        mfd3 = memfd_create("m3"); p3 = make_part(mfd3, b"cccc")

        publish(devfd, 0, make_parts_array(p1))
        h1 = head(devfd, 0); seq1 = h1.out_seqno
        publish(devfd, 0, make_parts_array(p2))
        publish(devfd, 0, make_parts_array(p3))

        h = head(devfd, 0)
        assert h.out_seqno != seq1  # oldest evicted

        f1, _ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
        f2, _ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
        with pytest.raises(OSError) as ex:
            fetch(devfd, 0, flags=KCLIP_FETCH_F_NONBLOCK | KCLIP_FETCH_F_POP)
        assert ex.value.errno == errno.EAGAIN

        os.close(mfd1); os.close(mfd2); os.close(mfd3)


def test_eviction_policy_reject(devfd):
    with temporary_limits(
        devfd,
        0,
        max_parts=8,
        max_depth=128,
        max_msg_bytes=64,
        max_bytes_total=6,
        policy_flags=KCLIP_LIMITS_F_REJECT,
    ):
        mfd1 = memfd_create("m1"); p1 = make_part(mfd1, b"aaaa")
        mfd2 = memfd_create("m2"); p2 = make_part(mfd2, b"bbbb")
        publish(devfd, 0, make_parts_array(p1))
        with pytest.raises(OSError) as ex:
            publish(devfd, 0, make_parts_array(p2))
        assert ex.value.errno == errno.ENOSPC

        h = head(devfd, 0)
        assert h.out_total_size == 4

        os.close(mfd1); os.close(mfd2)


# ===== PEEK vs POP, ACK, CONSUME semantics =====
def test_peek_leaves_message_pop_removes(devfd):
    mfd = memfd_create("peekpop"); p = make_part(mfd, b"hi")
    publish(devfd, 0, make_parts_array(p))

    f,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK)
    seq = f.out_seqno
    assert head(devfd, 0).out_seqno == seq

    f2,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    assert f2.out_seqno == seq

    with pytest.raises(OSError) as ex:
        fetch(devfd, 0, flags=KCLIP_FETCH_F_NONBLOCK | KCLIP_FETCH_F_POP)
    assert ex.value.errno == errno.EAGAIN
    os.close(mfd)


def test_ack_specific_seqno_and_double_ack(devfd):
    m1 = memfd_create("a"); p1 = make_part(m1, b"a")
    m2 = memfd_create("b"); p2 = make_part(m2, b"b")
    publish(devfd, 0, make_parts_array(p1))
    publish(devfd, 0, make_parts_array(p2))

    f,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK)
    seq1 = f.out_seqno
    ack(devfd, 0, seq1)

    f2,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK)
    assert f2.out_seqno != seq1

    with pytest.raises(OSError) as ex:
        ack(devfd, 0, seq1)
    assert ex.value.errno == errno.ENOENT

    fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    os.close(m1); os.close(m2)


def test_ack_after_pop_is_enonent(devfd):
    m = memfd_create("x"); p = make_part(m, b"x")
    publish(devfd, 0, make_parts_array(p))
    f,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    with pytest.raises(OSError) as ex:
        ack(devfd, 0, f.out_seqno)
    assert ex.value.errno == errno.ENOENT
    os.close(m)


def test_consume_seqno_zero_consumes_head(devfd):
    m1 = memfd_create("h"); p1 = make_part(m1, b"h")
    m2 = memfd_create("t"); p2 = make_part(m2, b"t")
    publish(devfd, 0, make_parts_array(p1))
    publish(devfd, 0, make_parts_array(p2))

    h1 = head(devfd, 0).out_seqno
    consume(devfd, 0, 0)  # remove head
    h2 = head(devfd, 0).out_seqno
    assert h2 != 0 and h2 != h1

    fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    os.close(m1); os.close(m2)


def test_consume_middle_removes_that_one(devfd):
    m1 = memfd_create("1"); p1 = make_part(m1, b"1")
    m2 = memfd_create("2"); p2 = make_part(m2, b"2")
    m3 = memfd_create("3"); p3 = make_part(m3, b"3")
    publish(devfd, 0, make_parts_array(p1))
    publish(devfd, 0, make_parts_array(p2))
    publish(devfd, 0, make_parts_array(p3))

    f1,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK)
    seq1 = f1.out_seqno

    fpop,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    assert fpop.out_seqno == seq1

    f2,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_PEEK)
    seq2 = f2.out_seqno

    consume(devfd, 0, seq2)

    f_after,_ = fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
    assert f_after.out_seqno != seq2

    with pytest.raises(OSError) as ex:
        fetch(devfd, 0, flags=KCLIP_FETCH_F_NONBLOCK | KCLIP_FETCH_F_POP)
    assert ex.value.errno == errno.EAGAIN

    os.close(m1); os.close(m2); os.close(m3)


def test_consume_nonexistent_seqno_enonent(devfd):
    with pytest.raises(OSError) as ex:
        consume(devfd, 0, 123456789)
    assert ex.value.errno == errno.ENOENT


def test_slot_list_reports_depth_and_bytes(devfd):
    drain_slot(devfd, slot=1)
    mfd = memfd_create("slotlist")
    try:
        payload = b"xy"
        part = make_part(mfd, payload)
        publish(devfd, 1, make_parts_array(part))

        hdr, entries = slot_list(devfd, in_cap=2)
        assert hdr.out_count == 2
        assert entries[0].slot_id == 0
        assert entries[0].depth == 0
        assert entries[1].slot_id == 1
        assert entries[1].depth == 1
        assert entries[1].bytes == len(payload)

        fetch(devfd, 1, flags=KCLIP_FETCH_F_POP)
    finally:
        os.close(mfd)
        drain_slot(devfd, slot=1)


def test_stats_get_tracks_activity(devfd):
    payload = b"stats" * 2
    before = stats_get(devfd, 0)
    lim = get_limits(devfd, 0)
    overrides = {}
    if lim.max_msg_bytes < len(payload):
        overrides["max_msg_bytes"] = len(payload)
    if lim.max_bytes_total < len(payload):
        overrides["max_bytes_total"] = len(payload) * 2
    with temporary_limits(devfd, 0, **overrides):
        mfd = memfd_create("stats")
        try:
            part = make_part(mfd, payload)
            publish(devfd, 0, make_parts_array(part))

            after_pub = stats_get(devfd, 0)
            assert after_pub.depth == before.depth + 1
            assert after_pub.bytes == before.bytes + len(payload)
            assert after_pub.enqueued == before.enqueued + 1

            fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)

            after_pop = stats_get(devfd, 0)
            assert after_pop.depth == before.depth
            assert after_pop.bytes == before.bytes
            assert after_pop.enqueued == before.enqueued + 1
            assert after_pop.dequeued == before.dequeued + 1
            assert after_pop.dropped == before.dropped
        finally:
            os.close(mfd)


def test_eventfd_register_and_unregister(devfd):
    efd = eventfd_create(0)
    try:
        flags = fcntl.fcntl(efd, fcntl.F_GETFL)
        fcntl.fcntl(efd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        eventfd_config(devfd, 0, efd)
        mfd1 = memfd_create("evt1")
        try:
            part1 = make_part(mfd1, b"evt")
            publish(devfd, 0, make_parts_array(part1))

            data = os.read(efd, 8)
            assert int.from_bytes(data, "little") == 1

            fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
        finally:
            os.close(mfd1)

        eventfd_config(devfd, 0, -1)

        mfd2 = memfd_create("evt2")
        try:
            part2 = make_part(mfd2, b"evt2")
            publish(devfd, 0, make_parts_array(part2))

            with pytest.raises(BlockingIOError):
                os.read(efd, 8)

            fetch(devfd, 0, flags=KCLIP_FETCH_F_POP)
        finally:
            os.close(mfd2)
    finally:
        os.close(efd)


def test_bind_slot_affects_poll(devfd):
    fd_poll = os.open(DEV_PATH, os.O_RDWR)
    try:
        drain_slot(devfd, slot=1)
        drain_slot(fd_poll, slot=1)

        bind_slot(fd_poll, 1)
        poller = select.poll()
        poller.register(fd_poll, select.POLLIN)
        assert poller.poll(0) == []

        mfd = memfd_create("bindpoll")
        try:
            part = make_part(mfd, b"bp")
            publish(devfd, 1, make_parts_array(part))

            events = poller.poll(100)
            assert events and events[0][0] == fd_poll and events[0][1] & select.POLLIN

            fetch(devfd, 1, flags=KCLIP_FETCH_F_POP)
        finally:
            os.close(mfd)
            drain_slot(devfd, slot=1)
    finally:
        os.close(fd_poll)
