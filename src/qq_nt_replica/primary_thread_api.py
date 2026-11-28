from dataclasses import dataclass

from .errors import InputError


@dataclass(frozen=True)
class RawCreateThreadObservation:
    arguments: tuple[int, int, int, int, int, int]
    result: int
    thread_id_write: bytes | None

    def __post_init__(self):
        if (type(self.arguments) is not tuple or len(self.arguments) != 6 or
                any(type(value) is not int or not 0 <= value < 1 << 64
                    for value in self.arguments) or
                type(self.result) is not int or not 0 <= self.result < 1 << 64):
            raise InputError('raw CreateThread requires six unsigned64 slots and a full unsigned64 result')
        if self.result and self.arguments[5]:
            if type(self.thread_id_write) is not bytes or len(self.thread_id_write) != 4:
                raise InputError('successful raw CreateThread nonnull output requires exactly four observed bytes')
        elif self.thread_id_write is not None:
            raise InputError('raw CreateThread null output or failure requires explicit no-write effect')


def apply_observation(runtime, observation, arguments):
    if type(observation) is not RawCreateThreadObservation or observation.arguments != arguments:
        raise InputError('raw CreateThread observation arguments do not match actual slots')
    if observation.thread_id_write is not None:
        runtime.memory.write(arguments[5], observation.thread_id_write,
                             source='CreateThread.observed_thread_id_DWORD')
    event = (*arguments, observation.result)
    runtime.thread_starts.append(event)
    runtime.events.append(('CreateThread.observed', *event))
    return observation.result
