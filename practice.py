# practice.py

# 1) Failure rate calculator
def calculate_failure(total_attempts, failed_attempts):
    rate = failed_attempts / total_attempts
    print("Rate of failure so far is:", rate)
    return rate

fail_rate = calculate_failure(100, 28)

if fail_rate > 0.30:
    print("Rate is above 30%. Do something about it.")
else:
    print("Rate is below 30%. You're okay for now.")


print()  # blank line for readability


# 2) Reading rate calculator
def reading_rate(number_of_days, days_read):
    rate = days_read / number_of_days
    print("Your rate of reading is:", rate)
    return rate

lockin_rate = reading_rate(115, 30)

if lockin_rate < 0.50:
    print("Awful, brother. Lock in harder. Zero days wasted this month. MINIMUM.")
else:
    print("Nailing it man!")