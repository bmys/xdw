CREATE TABLE suspicion (
    suspicion_id integer NOT NULL,
    event text NOT NULL CHECK (event IN ('http_flood')),
    time text NOT NULL,
    suspicious_ip text NOT NULL,
    attacked_port integer,
    protocol text NOT NULL,

    PRIMARY KEY (suspicion_id)
);

CREATE TABLE filter_rule (
    rule_id integer NOT NULL,
    suspicion_id integer NOT NULL,
    enable_time text NOT NULL,

    PRIMARY KEY (rule_id),
    FOREIGN KEY (suspicion_id) REFERENCES suspicion (suspicion_id)
);
