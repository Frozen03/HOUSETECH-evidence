-- HOUSETECH role seed (Owner + CEO)
CREATE TABLE IF NOT EXISTS user_org_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('Owner','CEO','Founder','Admin','Manager','Tech','Accounting','vodja','zaposlen','študent'))
);
INSERT INTO user_org_roles (org_id, email, role) VALUES
  ('00000000-0000-0000-0000-000000000001','info@housetech.si','Owner'),
  ('00000000-0000-0000-0000-000000000001','info@housetech.si','CEO'),
  ('00000000-0000-0000-0000-000000000001','jon.rutar@gmail.com','Owner'),
  ('00000000-0000-0000-0000-000000000001','jon.rutar@gmail.com','CEO'),
  ('00000000-0000-0000-0000-000000000001','nace.mlakar46@gmail.com','Owner'),
  ('00000000-0000-0000-0000-000000000001','nace.mlakar46@gmail.com','CEO')
ON CONFLICT DO NOTHING;
