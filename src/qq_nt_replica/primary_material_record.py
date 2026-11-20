from .primary_material_context import _steps


def prepare_primary_material_record(vm):
    from .primary_record_frames import run_primary_seed_record_frame

    return run_primary_seed_record_frame(vm)
