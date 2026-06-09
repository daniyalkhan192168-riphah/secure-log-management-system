from database import SessionLocal
from models import Log
from services.hash_service import generate_hash

db = SessionLocal()
logs = db.query(Log).order_by(Log.id.asc()).all()
print('Total logs:', len(logs))

expected = 'GENESIS'
for log in logs:
    log_data = {
        'timestamp': log.timestamp.isoformat() if log.timestamp else 'NOW',
        'source': log.source,
        'event_type': log.event_type,
        'username': log.username,
        'ip_address': log.ip_address,
        'message': log.message
    }
    recalc = generate_hash(log_data, log.previous_hash)
    match = 'OK' if recalc == log.current_hash else 'MISMATCH'
    prev_ok = 'OK' if log.previous_hash == expected else 'PREV_WRONG'
    print(f'ID:{log.id} prev:{prev_ok} hash:{match} prev_hash:{log.previous_hash[:8]}')
    expected = log.current_hash