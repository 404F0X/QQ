from dataclasses import asdict, dataclass

from .local113_episode_validation import require


@dataclass(frozen=True)
class PublicLocal113Result:
    schema: str
    captureMode: str
    stage: str
    comparisonStatus: str
    firstDifference: int | None
    rejectCode: str | None
    frameCount: int
    chargedSteps: int
    cleanup: dict
    diagnosticOnly: bool
    actualQualified: bool

    def to_public(self):
        require(self.firstDifference is None or type(self.firstDifference) is int and 0 <= self.firstDifference < 16, 'PROJECTION_DIFFERENCE')
        require(self.actualQualified is False and type(self.diagnosticOnly) is bool, 'PROJECTION_QUALIFICATION')
        return asdict(self)


def project(episode, result, diagnostic):
    from .local113_episode_inputs import _validate_cleanup
    cleanup = _validate_cleanup(dict(sealedAt=9563, collectionClosed=True, dropped=0, cleanup=episode.cleanup), diagnostic)
    difference = next((i for i, (a, b) in enumerate(zip(result.local113, episode.reference)) if a != b), None)
    require(len(result.local113) == len(episode.reference) == 16, 'LOCAL113_COMPARISON_WIDTH')
    return PublicLocal113Result('local113-live-result-v1', 'LOCAL113_PREFIX9563', 'PC9564', 'EQUAL' if difference is None else 'MISMATCH', difference, None, len(episode.frame_plan.sources), result.charged_steps, cleanup, diagnostic, False)
