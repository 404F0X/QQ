"""9EEF9 file result and separately diagnosed same-file DACL attempt."""
from .primary_qimei_request import QimeiRequestBoundary
from .primary_qimei_settings import RECORD_SIZE


class QimeiSettingsWriter:
    def __init__(self, backend, codec, context_producer, observations, *, attempted=None):
        self.backend,self.codec = backend,codec
        self.context_producer,self.observations = context_producer,observations
        self.__attempted = set() if attempted is None else attempted
        if not isinstance(self.__attempted, set):
            raise QimeiRequestBoundary('shared Source ACL path cache required')

    def save(self, path, record):
        self.backend.validate_path(path)
        if type(record) is not bytes or len(record) != RECORD_SIZE:
            raise QimeiRequestBoundary('complete settings record backing required')
        encoded = self.codec.encode_payload(record,context=self.context_producer.produce(self.observations))
        if encoded is None:
            return 1
        cipher = encoded.value
        if not cipher:
            return 3
        file = self.backend.open_file(path)
        if file is None:
            return 2
        try:
            written = self.backend.write_file(file,cipher)
        finally:
            self.backend.close_file(file)
        if written != len(cipher):
            return 2
        if path and self.backend.path_exists(path) and self.backend.is_admin() and path not in self.__attempted:
            self.backend.grant_same_file_access(path)
            self.__attempted.add(path)
        return 0
