from app import app, db, Agents, Administrator


def delete_agents():
	with app.app_context():
		agents = Agents.query.all()
		for agent in agents:
			db.session.delete(agent)
			print(f"Deleted: {agent.id}")
		db.session.commit()


def add_admin():
	with app.app_context():
		admin = Administrator(username="constant")
		admin.set_password("constant")
		db.session.add(admin)
		db.session.commit()
		print("New admin account has been created.")

#delete_agents()
#add_admin()

