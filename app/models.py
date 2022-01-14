from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, text, Numeric
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.expression import null

Base = declarative_base()
metadata = Base.metadata


class Clas(Base):
    __tablename__ = 'class'

    id = Column(UUID, primary_key=True)
    code = Column(String(255))
    name = Column(String(255))


class ScanStatu(Base):
    __tablename__ = 'scan_status'

    id = Column(UUID, primary_key=True)
    code = Column(String(250))
    name = Column(String(250))


class ScanType(Base):
    __tablename__ = 'scan_type'

    id = Column(UUID, primary_key=True)
    name = Column(String(250))
    code = Column(String(250))


class Dataset(Base):
    __tablename__ = 'dataset'

    id = Column(UUID, primary_key=True)
    scan_type_id = Column(ForeignKey('scan_type.id'), nullable=False)
    os = Column(String(255))
    file = Column(String(255))
    name = Column(String(255))
    family = Column(String(255), nullable=False)

    scan_type = relationship('ScanType')


class Scan(Base):
    __tablename__ = 'scan'

    id = Column(UUID, primary_key=True)
    started_at = Column(DateTime)
    ended_at = Column(DateTime)
    created_by = Column(String(255), nullable=True)
    scan_status_id = Column(ForeignKey('scan_status.id'), nullable=False)
    reference = Column(UUID, nullable=True)

    scan_status = relationship('ScanStatu')


class Profile(Base):
    __tablename__ = 'profile'

    id = Column(UUID, primary_key=True)
    dataset_id = Column(ForeignKey('dataset.id'), nullable=False)
    code = Column(String(255))
    name = Column(String(255))

    dataset = relationship('Dataset')


class Result(Base):
    __tablename__ = 'result'

    id = Column(UUID, primary_key=True)
    scan_id = Column(ForeignKey('scan.id'), nullable=False)
    class_id = Column(ForeignKey('class.id'), nullable=False)
    title = Column(String(1000))
    description = Column(String(6000))
    status = Column(Boolean, nullable=False, server_default=text("false"))
    score = Column(String(6000))
    fix_available = Column(Boolean, nullable=False, server_default=text("false"))
    impact = Column(String(1000))
    reference = Column(UUID, nullable=True)

    _class = relationship('Clas')
    scan = relationship('Scan')


class Reference(Base):
    __tablename__ = 'reference'

    id = Column(UUID, primary_key=True)
    type_code = Column(String(255))
    name = Column(String(255))
    code = Column(String(255))
    url = Column(String(500))
    result_id = Column(ForeignKey('result.id'), nullable=False)

    result = relationship('Result')


class O(Base):
    __tablename__ = 'osr'

    os = Column(String, primary_key=True)


class Definition(Base):
    __tablename__ = 'definition'

    id = Column(UUID, primary_key=True)
    cve = Column(String, nullable=False)
    cwe = Column(String, nullable=False)
    description = Column(String(20000), nullable=False)
    score = Column(Numeric(10, 2), nullable=False)
    exploit_count = Column(Integer, nullable=False)
    url = Column(String(500), nullable=False)
    publish_date = Column(DateTime, nullable=False)
