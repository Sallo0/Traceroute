class ICMPReply:
    __slots__ = "_source", "_family", "_id", "_sequence", "_type", "_code", "_bytes_received", "_time"

    def __init__(self, source, family, id, sequence, type, code, bytes_received, time):

        self._source = source
        self._family = family
        self._id = id
        self._sequence = sequence
        self._type = type
        self._code = code
        self._bytes_received = bytes_received
        self._time = time

    def raise_for_status(self):
        if self._type == 3:
            raise ConnectionResetError

        if self._type == 11:
            raise TimeoutError

        if self._type != 0:
            message = f"Error type: {self._type}, code: {self._code}"
            raise OSError(message)

    @property
    def source(self):
        return self._source

    @property
    def id(self):
        return self._id

    @property
    def sequence(self):
        return self._sequence

    @property
    def type(self):
        return self._type

    @property
    def code(self):
        return self._code

    @property
    def bytes_received(self):
        return self._bytes_received

    @property
    def time(self):
        return self._time
