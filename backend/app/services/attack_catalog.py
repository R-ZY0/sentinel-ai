from attack_engine.normalized_attack_library import NORMALIZED_ATTACK_LIBRARY
from sqlalchemy import select
from ..models import Attack


def sync_catalog(db):
    definitions = [dict(id=item.attack_id, name=item.attack_id, category=item.category,
        engine="library", payload=item.payload, strategy=item.strategy,
        expected_behavior=item.expected_behavior) for item in NORMALIZED_ATTACK_LIBRARY]
    for id, engine, category in [("PYRIT-PI-001", "pyrit", "Prompt Injection"),
                                  ("GARAK-DAN-001", "garak", "Jailbreak")]:
        definitions.append(dict(id=id, name=id, engine=engine, category=category,
            payload="Tool-managed probe", strategy=engine,
            expected_behavior="Protect the server-planted synthetic canary"))
    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        # Concurrent requests may seed the same catalog. Preserve existing rows,
        # including a maintainer's disabled attack or edited definition.
        db.execute(insert(Attack).values(definitions).on_conflict_do_nothing(index_elements=["id"]))
    else:
        for definition in definitions:
            if db.get(Attack, definition["id"]) is None:
                db.add(Attack(**definition))
    db.flush()


def select_attacks(db, config):
    sync_catalog(db)
    all_attacks = {item.id: item for item in db.scalars(select(Attack)).all()}
    default_ids = {"library": "SPL-001", "pyrit": "PYRIT-PI-001", "garak": "GARAK-DAN-001"}
    ids = config.attack_ids or [default_ids[engine] for engine in config.engines]
    attacks = []
    for id in ids:
        item = all_attacks.get(id)
        if item is None or not item.active or item.engine not in config.engines:
            raise ValueError("Unknown, inactive or engine-incompatible attack selection")
        if config.pipeline == "week34":
            from .week34_scenarios import CASE_BY_ATTACK
            if id not in CASE_BY_ATTACK:
                raise ValueError("Attack has no trusted Week 3-4 scenario mapping")
        attacks.append(item)
    if set(config.engines) != {attack.engine for attack in attacks}:
        raise ValueError("Each selected engine must have an attack selected")
    return attacks
